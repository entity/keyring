<?php

declare(strict_types=1);

namespace Keyring\Changes;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Validation\ValidationException;
use Keyring\Contracts\Enrollable;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Events\AuthenticatorAdded;
use Keyring\Events\AuthenticatorRemovalRefused;
use Keyring\Events\AuthenticatorRemoved;
use Keyring\Events\RecoveryCodesGenerated;
use Keyring\Factors\RecoveryCodes;
use Keyring\KeyringManager;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use Keyring\Sessions\Sessions;
use Keyring\Support\PasswordRules;
use Keyring\Support\RowLock;

/**
 * Adding, changing and removing a user's authenticators, and the rules that
 * keep what's left usable.
 */
class AuthenticatorChanges
{
    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
    ) {}

    /**
     * Save a newly confirmed authenticator. A factor that allows one per user
     * replaces the old one, the first sign-in method becomes the default, and
     * the first extra factor comes with recovery codes (as does one added
     * once they've run out), whose plain codes are returned to show once.
     * An emailed code isn't a factor, so it comes with none: there would be
     * nothing for them to recover.
     *
     * With the request it came in, the session that asked has to still be
     * signed in when it's saved: one ended while the request ran (an email
     * change undone, say) adds nothing.
     *
     * @return list<string>|null
     *
     * @throws AuthenticationException
     */
    public function add(Authenticatable&Model $user, Enrollable $factor, Authenticator $authenticator, ?Request $request = null): ?array
    {
        $keyring = $this->keyring->for($user);
        $isRecovery = $factor->key() === RecoveryCodes::KEY;
        $recoverable = array_any($factor->categories($authenticator), fn (Category $category) => $category->authenticates());
        $recovery = ! $isRecovery && $recoverable && ! $keyring->hasRecoveryCodes() ? $this->recoveryCodes() : null;

        $save = fn () => $authenticator->getConnection()->transaction(function () use ($factor, $user, $keyring, $authenticator, $isRecovery, $recovery) {
            if (! $factor->multiple()) {
                $replaced = $keyring->of($factor->key())->each->delete();

                // New recovery codes are upkeep, not a change of sign-in method.
                if (! $isRecovery && $replaced->isNotEmpty()) {
                    $this->sessions->distrustDevices($user);
                }
            }

            $this->save($user, $authenticator, default: ! $isRecovery && $keyring->default() === null);

            if ($recovery !== null) {
                $keyring->of(RecoveryCodes::KEY)->each->delete();
                $this->save($user, $recovery['authenticator']);
            }
        });

        $request === null ? $save() : $this->sessions->whileSignedIn($request, $user, $save);

        $isRecovery
            ? RecoveryCodesGenerated::dispatch($user, $authenticator)
            : AuthenticatorAdded::dispatch($user, $authenticator);

        if ($recovery !== null) {
            RecoveryCodesGenerated::dispatch($user, $recovery['authenticator']);
        }

        return $recovery['codes'] ?? null;
    }

    /**
     * Rename an authenticator, or make it (or stop it being) the default.
     *
     * @param  array{name?: string, default?: bool}  $changes
     */
    public function update(Authenticator $authenticator, array $changes): void
    {
        $authenticator->getConnection()->transaction(function () use ($authenticator, $changes) {
            if ($changes['default'] ?? false) {
                $this->keyring->for($authenticator->user())->all()
                    ->filter(fn (Authenticator $other) => $other->exists && $other->is_default)
                    ->each(fn (Authenticator $other) => $other->forceFill(['is_default' => false])->save());
            }

            $authenticator->fill(Arr::only($changes, 'name'));

            if (array_key_exists('default', $changes)) {
                $authenticator->is_default = (bool) $changes['default'];
            }

            $authenticator->save();
        });
    }

    /**
     * Remove an authenticator, unless that would leave the user unable to
     * sign in the way their policy requires. One removal per user runs at a
     * time, so two at once can't each count on the other's authenticator
     * still being there.
     *
     * @throws ValidationException
     */
    public function remove(Authenticatable&Model $user, string $id, #[\SensitiveParameter] ?string $password = null): Authenticator
    {
        [$authenticator, $removed] = RowLock::hold($user, function () use ($user, $id, $password) {
            $authenticator = $this->owned($user, $id);

            if ($authenticator === null) {
                return [null, false];
            }

            $keyring = $this->keyring->for($user);
            $remaining = $keyring->without($authenticator);

            // Recovery codes are only useful while there's a second factor to
            // recover, so they go too when this was the last one. The policy
            // is checked against what will actually be left.
            $onlyRecoveryLeft = ! $remaining->hasFactorToRecover();
            $cascade = $onlyRecoveryLeft ? $remaining->of(RecoveryCodes::KEY)->all() : [];
            $left = $remaining->without(...$cascade);

            $policy = $this->keyring->policy($user, Attempt::start(Purpose::Login, $user));

            if (! $left->canSignIn() || (! $policy->onlyIfEnrolled && ! $left->canMeet($policy))) {
                return [$authenticator, false];
            }

            if ($keyring->hasSecondFactor() && ! $left->hasSecondFactor()) {
                $this->ensurePasswordStandsAlone($user, $password);
            }

            collect([$authenticator, ...$cascade])->each->delete();
            $this->sessions->distrustDevices($user);

            return [$authenticator, true];
        });

        // Refused out here, once the lock's transaction is over: a log entry
        // written inside it would be rolled back with it.
        if ($authenticator === null) {
            $this->keyring->authenticatorModel()::refuse($user, $id);
        }

        if (! $removed) {
            AuthenticatorRemovalRefused::dispatch($user, $authenticator);

            throw ValidationException::withMessages(['authenticator' => __('keyring::keyring.last_factor')]);
        }

        AuthenticatorRemoved::dispatch($user, $authenticator);

        return $authenticator;
    }

    /**
     * The password may have been as short as min_with_mfa while it had a
     * second factor beside it. On its own it needs min_without_mfa, and only
     * the user can say how long it is, so removing the last second factor
     * takes it, typed again.
     *
     * @throws ValidationException
     */
    protected function ensurePasswordStandsAlone(Authenticatable&Model $user, #[\SensitiveParameter] ?string $password): void
    {
        if (blank($user->getAuthPassword())) {
            return;
        }

        if ($password === null || ! $this->keyring->provider()->validateCredentials($user, ['password' => PasswordRules::forVerifying($password, $user->getAuthPassword())])) {
            throw ValidationException::withMessages(['password' => __('keyring::keyring.password_to_remove_last_factor')]);
        }

        $min = PasswordRules::min();

        if (mb_strlen(PasswordRules::normalize($password)) < $min) {
            throw ValidationException::withMessages(['password' => __('keyring::keyring.password_too_short_alone', ['min' => $min])]);
        }
    }

    /**
     * One of the user's authenticators. Asking for any other is a 404, and
     * goes on record.
     */
    public function find(Authenticatable&Model $user, string $id): Authenticator
    {
        return $this->owned($user, $id) ?? $this->keyring->authenticatorModel()::refuse($user, $id);
    }

    protected function owned(Authenticatable&Model $user, string $id): ?Authenticator
    {
        return $this->keyring->authenticatorModel()::query()
            ->ownedBy($user)
            ->find($id)
            ?->setRelation('authenticatable', $user);
    }

    /**
     * A fresh set of recovery codes to hand out with the first extra factor.
     *
     * @return array{codes: list<string>, authenticator: Authenticator}|null
     */
    protected function recoveryCodes(): ?array
    {
        $factor = $this->keyring->registered()->get(RecoveryCodes::KEY);

        if (! $factor instanceof RecoveryCodes) {
            return null;
        }

        ['codes' => $codes, 'secret' => $secret] = $factor->generate();

        return ['codes' => $codes, 'authenticator' => $factor->make($secret)];
    }

    protected function save(Authenticatable&Model $user, Authenticator $authenticator, bool $default = false): void
    {
        $authenticator->authenticatable()->associate($user);
        $authenticator->forceFill(['confirmed_at' => now(), 'is_default' => $default])->save();
    }
}
