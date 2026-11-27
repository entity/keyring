<?php

declare(strict_types=1);

namespace Keyring\Changes;

use Carbon\CarbonImmutable;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Illuminate\Validation\ValidationException;
use Keyring\Contracts\Enrollable;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Enums\Category;
use Keyring\Enums\FreezeReason;
use Keyring\Enums\Purpose;
use Keyring\Events\AuthenticatorAdded;
use Keyring\Events\AuthenticatorRemovalRefused;
use Keyring\Events\AuthenticatorRemoved;
use Keyring\Events\EnrollmentRefused;
use Keyring\Events\RecoveryCodesGenerated;
use Keyring\Exceptions\PasswordRequired;
use Keyring\Exceptions\SignInChangesFrozen;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\KeyringManager;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use Keyring\Models\SignInChange;
use Keyring\Sessions\Sessions;
use Keyring\Support\Duration;
use Keyring\Support\FactorCheck;
use Keyring\Support\PasswordRules;
use Keyring\Support\RowLock;
use Keyring\UserKeyring;

/**
 * Adding, changing and removing a user's authenticators, and the rules that
 * keep what's left usable.
 */
class AuthenticatorChanges
{
    /**
     * In a factor's meta: add() saved it without the password checked for
     * it, so a copy of a session could have added it. UserKeyring::reachable()
     * never asks for one with it before it's established.
     */
    public const string ADDED_WITHOUT_PASSWORD = 'added_without_password';

    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
        protected FactorCheck $checks,
    ) {}

    /**
     * Save a newly confirmed authenticator. A factor that allows one per user
     * replaces the old one, the first sign-in method becomes the default, and
     * the first extra factor comes with recovery codes (as does one added
     * once they've run out), whose plain codes are returned to show once.
     * An emailed code isn't a factor, so it comes with none: there would be
     * nothing for them to recover. Nor does a factor that only starts a sign
     * in, like an identity provider, which is never the default either.
     *
     * Replacing recovery codes or a factor the account has had for a while
     * is refused while the account is frozen(), unless $ignoreFreeze says
     * otherwise, and freezes it in turn. That's for an app's own support
     * tools, and for a request that proved an established method for this
     * change (see FreezeSkips), never a user's say-so.
     *
     * A factor added to an account that has no established second factor
     * needs the password, typed for this enrollment: see needsPassword().
     * $passwordConfirmed says it was, as the enrollment routes check with
     * confirmPassword() when it begins. Your own code passes it once it has
     * made sure who it's adding for some other way. A factor saved without
     * it keeps that (ADDED_WITHOUT_PASSWORD): a copy of a session could
     * have added it, so an ifEnrolled() policy never asks for it until it's
     * established, whatever happens to the password since (see
     * UserKeyring::reachable()).
     *
     * With the request it came in, the session that asked has to still be
     * signed in when it's saved: one ended while the request ran (an email
     * change undone, say) adds nothing.
     *
     * @return list<string>|null
     *
     * @throws AuthenticationException
     * @throws PasswordRequired
     * @throws SignInChangesFrozen
     */
    public function add(Authenticatable&Model $user, Enrollable $factor, Authenticator $authenticator, ?Request $request = null, bool $ignoreFreeze = false, bool $passwordConfirmed = false): ?array
    {
        $keyring = $this->keyring->for($user);
        $isRecovery = $factor->key() === RecoveryCodes::KEY;
        // One that can only start a sign in, like an identity provider, is
        // never asked for as a second step: no code would stand in for it,
        // and it's never the one a challenge offers first.
        $challengeable = ! $factor instanceof PrimaryFactor || $factor->answersChallenges();
        $recoverable = $challengeable && array_any($factor->categories($authenticator), fn (Category $category) => $category->authenticates());
        $recovery = ! $isRecovery && $recoverable && ! $keyring->hasRecoveryCodes() ? $this->recoveryCodes() : null;

        // One change to a user's sign-in methods at a time, so two can't each
        // find the account unfrozen.
        $save = fn () => $authenticator->getConnection()->transaction(function () use ($factor, $user, $authenticator, $isRecovery, $challengeable, $recovery, $ignoreFreeze, $passwordConfirmed) {
            $keyring = $this->keyring->for($user);

            // Checked again here, where no other change can come between: a
            // factor that was established when the enrollment began may have
            // gone since.
            if (! $passwordConfirmed && $this->isFactor($factor, $authenticator) && $this->needsPasswordFor($user, $keyring)) {
                throw $this->passwordRequired();
            }

            $replaced = $factor->multiple() ? collect() : $keyring->of($factor->key());
            $lost = $recovery === null ? $replaced : $replaced->merge($keyring->of(RecoveryCodes::KEY));

            $destructive = $this->ensureMayLose($user, $keyring, $lost, $ignoreFreeze);

            $replaced->each->delete();

            // New recovery codes are upkeep, not a change of sign-in method.
            if (! $isRecovery && $replaced->isNotEmpty()) {
                $this->sessions->distrustDevices($user);
            }

            if (! $passwordConfirmed && $this->isFactor($factor, $authenticator)) {
                $authenticator->withMeta(self::ADDED_WITHOUT_PASSWORD, true);
            }

            $this->save($user, $authenticator, default: ! $isRecovery && $challengeable && $keyring->default() === null);

            if ($recovery !== null) {
                $keyring->of(RecoveryCodes::KEY)->each->delete();
                $this->save($user, $recovery['authenticator']);
            }

            if ($destructive) {
                $this->recordChange($user);
            }
        });

        try {
            $request === null ? RowLock::hold($user, $save) : $this->sessions->whileSignedIn($request, $user, $save);
        } catch (SignInChangesFrozen $e) {
            // Out here, once the lock's transaction is over: a log entry
            // written inside it would be rolled back with it.
            EnrollmentRefused::dispatch($user, $factor->key(), 'frozen');

            throw $e;
        } catch (PasswordRequired $e) {
            EnrollmentRefused::dispatch($user, $factor->key(), 'password');

            throw $e;
        }

        $isRecovery
            ? RecoveryCodesGenerated::dispatch($user, $authenticator)
            : AuthenticatorAdded::dispatch($user, $authenticator);

        if ($recovery !== null) {
            RecoveryCodesGenerated::dispatch($user, $recovery['authenticator']);
        }

        return $recovery['codes'] ?? null;
    }

    /**
     * Refuse to start adding a factor that would replace something the
     * account counts on while it's frozen, such as new recovery codes, so
     * the user isn't shown codes that can't be saved. add() checks again.
     *
     * @throws SignInChangesFrozen
     */
    public function ensureMayAdd(Authenticatable&Model $user, Enrollable $factor): void
    {
        $keyring = $this->keyring->for($user);

        if (! $factor->multiple() && $keyring->of($factor->key())->contains(fn (Authenticator $old) => $this->countedOn($keyring, $old))) {
            $freeze = $this->frozen($user);

            if ($freeze !== null) {
                EnrollmentRefused::dispatch($user, $factor->key(), 'frozen');

                throw new SignInChangesFrozen($freeze);
            }
        }
    }

    /**
     * Whether adding the factor takes the user's password, typed again for
     * it. A session alone could otherwise give a password-only account a
     * second factor its owner doesn't have, and then they'd be asked for it
     * at every sign in, or, for a passkey, have someone else able to sign
     * in without the password at all. A password reset wouldn't undo it.
     *
     * So it's needed when the factor is one (not recovery codes or an
     * emailed code) and the account has no established second factor:
     * only a password, or factors that are as new as one a session could
     * have added first. A recent verification doesn't count, since whoever
     * copied the session has that too.
     *
     * An account without a password, or whose app doesn't register the
     * password factor, has nothing to type, and adds one on the fresh
     * verification alone: a passkey it signs in with is a second factor
     * once it's established, and one that isn't yet can't be told from one
     * a session added. So does an account whose only password is a first
     * one set from a session and not established yet (see
     * UserKeyring::isEstablished()): whoever set it could type it, so it
     * proves nothing, and a factor added with it is no more asked for than
     * one added without.
     */
    public function needsPassword(Authenticatable&Model $user, Enrollable $factor): bool
    {
        $authenticator = new ($this->keyring->authenticatorModel())(['factor' => $factor->key()]);

        return $this->isFactor($factor, $authenticator) && $this->needsPasswordFor($user, $this->keyring->for($user));
    }

    /**
     * Check the password typed for adding the factor, under the password's
     * rate limits. A wrong one counts as a failed password, and goes on
     * record as one would at a step-up.
     *
     * @throws ValidationException
     */
    public function confirmPassword(Authenticatable&Model $user, Enrollable $factor, Request $request, #[\SensitiveParameter] ?string $password): void
    {
        if (! is_string($password) || $password === '') {
            EnrollmentRefused::dispatch($user, $factor->key(), 'password');

            throw $this->passwordRequired();
        }

        $passwords = $this->keyring->factor(Password::KEY);

        $checked = $this->checks->check(
            $request,
            Attempt::start(Purpose::Confirm, $user),
            $passwords,
            new Collection([Authenticator::virtual($passwords, $user, __('Password'))]),
            ['password' => $password],
            'password',
        );

        if ($checked === null) {
            EnrollmentRefused::dispatch($user, $factor->key(), 'password');

            throw ValidationException::withMessages(['password' => __('validation.current_password')]);
        }
    }

    protected function needsPasswordFor(Authenticatable&Model $user, UserKeyring $keyring): bool
    {
        $established = $keyring->established();

        return $established->of(Password::KEY)->isNotEmpty() && ! $established->hasSecondFactor();
    }

    /**
     * Whether the authenticator would be a factor of its own: not recovery
     * codes, or a step like an emailed code.
     */
    protected function isFactor(Enrollable $factor, Authenticator $authenticator): bool
    {
        return $factor->key() !== RecoveryCodes::KEY
            && array_any($factor->categories($authenticator), fn (Category $category) => $category->authenticates());
    }

    protected function passwordRequired(): PasswordRequired
    {
        return PasswordRequired::withMessages(['password' => __('keyring::keyring.password_to_add_factor')]);
    }

    /**
     * Why the user's established sign-in methods and recovery codes can't be
     * removed, replaced or renamed just now, and until when, or null when
     * they can. An account is frozen for "authenticator_changes.established_after"
     * after a factor is added, or a first password is set from a session
     * (see PasswordChanges::change()), as for any new sign-in method, and
     * after one it counted on is removed or replaced, so whoever got into a
     * session can't add a factor of their own and then take away the
     * owner's. Factors and recovery codes that
     * aren't established yet can always be removed or replaced, and new
     * recovery codes don't freeze anything on their own.
     */
    public function frozen(Authenticatable&Model $user): ?Freeze
    {
        $for = Duration::seconds(config('keyring.authenticator_changes.established_after'));
        $keyring = $this->keyring->for($user);
        $added = $keyring->all()
            ->reject(fn (Authenticator $authenticator) => $authenticator->factor === RecoveryCodes::KEY || $keyring->isEstablished($authenticator))
            ->max(fn (Authenticator $authenticator) => $authenticator->created_at?->getTimestamp());
        $changed = SignInChange::query()->ownedBy($user)->first()?->changed_at;

        return collect([
            $added === null ? null : new Freeze(FreezeReason::NewAuthenticator, CarbonImmutable::createFromTimestamp($added, now()->getTimezone())->addSeconds($for)),
            $changed === null ? null : new Freeze(FreezeReason::RecentChange, CarbonImmutable::instance($changed)->addSeconds($for)),
        ])
            ->filter(fn (?Freeze $freeze) => $freeze !== null && $freeze->until->isFuture())
            ->sortBy(fn (Freeze $freeze) => $freeze->until->getTimestamp())
            ->last();
    }

    /**
     * Whether losing these takes something the account counts on, refused
     * while it's frozen.
     *
     * @param  iterable<Authenticator>  $lost
     *
     * @throws SignInChangesFrozen
     */
    protected function ensureMayLose(Authenticatable&Model $user, UserKeyring $keyring, iterable $lost, bool $ignoreFreeze): bool
    {
        $destructive = collect($lost)->contains(fn (Authenticator $authenticator) => $this->countedOn($keyring, $authenticator));

        if ($destructive && ! $ignoreFreeze && ($freeze = $this->frozen($user)) !== null) {
            throw new SignInChangesFrozen($freeze);
        }

        return $destructive;
    }

    /**
     * Whether the account counts on it: a factor, or recovery codes with
     * some left, that it has had for "authenticator_changes.established_after".
     * Not an emailed code, which isn't a factor.
     */
    protected function countedOn(UserKeyring $keyring, Authenticator $authenticator): bool
    {
        return $keyring->isEstablished($authenticator)
            && array_any($authenticator->factor()->categories($authenticator), fn (Category $category) => $category->authenticates());
    }

    /**
     * Start the freeze over: the account just lost something it counted on.
     */
    protected function recordChange(Authenticatable&Model $user): void
    {
        SignInChange::query()->updateOrCreate(
            ['authenticatable_type' => $user->getMorphClass(), 'authenticatable_id' => $user->getKey()],
            ['changed_at' => now()],
        );
    }

    /**
     * Rename an authenticator, or make it (or stop it being) the default.
     *
     * Renaming one the account counts on is refused while the account is
     * frozen(), unless $ignoreFreeze says otherwise (see add()): otherwise
     * a session could give the owner's key a name that makes it look like
     * the one to remove, or its own the name of the owner's. Renaming a
     * newer one, or choosing the default, always works.
     *
     * @param  array{name?: string, default?: bool}  $changes
     *
     * @throws SignInChangesFrozen
     */
    public function update(Authenticator $authenticator, array $changes, bool $ignoreFreeze = false): void
    {
        $user = $authenticator->user();

        RowLock::hold($user, function () use ($user, $authenticator, $changes, $ignoreFreeze) {
            $keyring = $this->keyring->for($user);

            if (array_key_exists('name', $changes) && $changes['name'] !== $authenticator->name) {
                $this->ensureMayLose($user, $keyring, [$authenticator], $ignoreFreeze);
            }

            if ($changes['default'] ?? false) {
                $keyring->all()
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
     * Removing a factor the account has had for a while, or its recovery
     * codes, is refused while the account is frozen(), unless $ignoreFreeze
     * says otherwise, and freezes it in turn. That's for an app's own
     * support tools, and for a request that proved an established method
     * for this removal (see FreezeSkips), never a user's say-so. A factor that isn't established
     * yet can always go, so the owner can remove one someone else added.
     *
     * @throws ValidationException
     * @throws SignInChangesFrozen
     */
    public function remove(Authenticatable&Model $user, string $id, #[\SensitiveParameter] ?string $password = null, bool $ignoreFreeze = false): Authenticator
    {
        // A password given is checked before the lock, so a wrong one stays
        // counted whatever happens to the removal: the lock's transaction
        // would roll the count back with it. One that's missing is asked
        // for once the removal is otherwise allowed.
        $passwordChecked = $password !== null && $password !== ''
            && ($owned = $this->owned($user, $id)) !== null
            && $this->leavesNoSecondFactor($this->keyring->for($user), $owned)
            && $this->ensurePasswordStandsAlone($user, $password);

        [$authenticator, $removed, $frozen] = RowLock::hold($user, function () use ($user, $id, $ignoreFreeze, $passwordChecked) {
            $authenticator = $this->owned($user, $id);

            if ($authenticator === null) {
                return [null, false, null];
            }

            $keyring = $this->keyring->for($user);

            try {
                $destructive = $this->ensureMayLose($user, $keyring, [$authenticator], $ignoreFreeze);
            } catch (SignInChangesFrozen $e) {
                return [$authenticator, false, $e];
            }

            [$left, $cascade] = $this->leftAfter($keyring, $authenticator);

            $policy = $this->keyring->policy($user, Attempt::start(Purpose::Login, $user));

            if (! $left->canSignIn() || (! $policy->onlyIfEnrolled && ! $left->canMeet($policy))) {
                return [$authenticator, false, null];
            }

            // Without a password checked above, removing what's now the
            // last second factor asks for one. Decided here, where no other
            // change can come between.
            if (! $passwordChecked && $this->leavesNoSecondFactor($keyring, $authenticator) && $this->hasPassword($user)) {
                throw $this->passwordToRemove();
            }

            collect([$authenticator, ...$cascade])->each->delete();
            $this->sessions->distrustDevices($user);

            if ($destructive) {
                $this->recordChange($user);
            }

            return [$authenticator, true, null];
        });

        // Refused out here, once the lock's transaction is over: a log entry
        // written inside it would be rolled back with it.
        if ($authenticator === null) {
            $this->keyring->authenticatorModel()::refuse($user, $id);
        }

        if ($frozen !== null) {
            AuthenticatorRemovalRefused::dispatch($user, $authenticator, 'frozen');

            throw $frozen;
        }

        if (! $removed) {
            AuthenticatorRemovalRefused::dispatch($user, $authenticator);

            throw ValidationException::withMessages(['authenticator' => __('keyring::keyring.last_factor')]);
        }

        AuthenticatorRemoved::dispatch($user, $authenticator);

        return $authenticator;
    }

    /**
     * What's left once the authenticator is removed, and the recovery codes
     * that go with it. Recovery codes are only useful while there's a second
     * factor to recover, so they go too when this was the last one. The
     * policy is checked against what will actually be left.
     *
     * @return array{UserKeyring, list<Authenticator>}
     */
    protected function leftAfter(UserKeyring $keyring, Authenticator $authenticator): array
    {
        $remaining = $keyring->without($authenticator);
        $cascade = $remaining->hasFactorToRecover() ? [] : array_values($remaining->of(RecoveryCodes::KEY)->all());

        return [$remaining->without(...$cascade), $cascade];
    }

    protected function leavesNoSecondFactor(UserKeyring $keyring, Authenticator $authenticator): bool
    {
        return $keyring->hasSecondFactor() && ! $this->leftAfter($keyring, $authenticator)[0]->hasSecondFactor();
    }

    /**
     * The password may have been as short as min_with_mfa while it had a
     * second factor beside it. On its own it needs min_without_mfa, and only
     * the user can say how long it is, so removing the last second factor
     * takes it, typed again. It's checked under the password's rate limits,
     * and a wrong one counts as a failed password, as one would at a
     * step-up. True once it's checked, false when the user has none to
     * sign in with.
     *
     * @throws ValidationException
     */
    protected function ensurePasswordStandsAlone(Authenticatable&Model $user, #[\SensitiveParameter] string $password): bool
    {
        if (! $this->hasPassword($user)) {
            return false;
        }

        $passwords = $this->keyring->factor(Password::KEY);

        $checked = $this->checks->check(
            app(Request::class),
            Attempt::start(Purpose::Confirm, $user),
            $passwords,
            new Collection([Authenticator::virtual($passwords, $user, __('Password'))]),
            ['password' => $password],
            'password',
        );

        if ($checked === null) {
            throw $this->passwordToRemove();
        }

        $min = PasswordRules::min();

        if (mb_strlen(PasswordRules::normalize($password)) < $min) {
            throw ValidationException::withMessages(['password' => __('keyring::keyring.password_too_short_alone', ['min' => $min])]);
        }

        return true;
    }

    /**
     * Whether the user has a password to sign in with: one is set, and the
     * app registers the password factor.
     */
    protected function hasPassword(Authenticatable&Model $user): bool
    {
        return $this->keyring->hasFactor(Password::KEY) && filled($user->getAuthPassword());
    }

    protected function passwordToRemove(): ValidationException
    {
        return ValidationException::withMessages(['password' => __('keyring::keyring.password_to_remove_last_factor')]);
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
