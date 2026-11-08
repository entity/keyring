<?php

namespace Keyring\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Keyring\Contracts\Enrollable;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Enrollment\EnrollmentStore;
use Keyring\Enums\Purpose;
use Keyring\Events\AuthenticatorAdded;
use Keyring\Events\AuthenticatorRemoved;
use Keyring\Events\RecoveryCodesGenerated;
use Keyring\Factors\RecoveryCodes;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use Keyring\Support\RowLock;

/**
 * Adding, renaming, choosing the default and removing authenticators. One
 * set of routes for every factor.
 */
class AuthenticatorController
{
    use RespondsWithStatus;

    public function __construct(
        protected KeyringManager $keyring,
        protected EnrollmentStore $enrollments,
    ) {}

    /**
     * Begin enrolling: returns what the user needs to see (QR code, codes...).
     */
    public function store(Request $request, string $factor): StatusResponse
    {
        $factor = $this->enrollable($request, $factor);
        $enrollment = $factor->beginEnrollment($request->user(), $request);

        $this->enrollments->put($enrollment);

        return $this->status('enrollment-started', ['factor' => $factor->key(), 'enrollment' => $enrollment->props]);
    }

    /**
     * Finish enrolling once the user proves it works.
     */
    public function confirm(Request $request, string $factor): StatusResponse
    {
        $factor = $this->enrollable($request, $factor);
        $user = $request->user();

        $enrollment = $this->enrollments->get($factor->key())
            ?? throw ValidationException::withMessages([$factor->errorKey() => __('keyring::keyring.enrollment_expired')]);

        $request->validate($factor->enrollmentRules());

        $authenticator = $factor->confirmEnrollment($user, $enrollment, $request)
            ?? throw ValidationException::withMessages([$factor->errorKey() => __('keyring::keyring.invalid')]);

        $keyring = $this->keyring->for($user);
        $isRecovery = $factor->key() === RecoveryCodes::KEY;
        $recovery = ! $isRecovery && $keyring->of(RecoveryCodes::KEY)->isEmpty() ? $this->recoveryCodes() : null;

        DB::transaction(function () use ($factor, $user, $keyring, $authenticator, $isRecovery, $recovery) {
            if (! $factor->multiple()) {
                $keyring->of($factor->key())->each->delete();
            }

            $this->save($user, $authenticator, default: ! $isRecovery && $keyring->default() === null);

            if ($recovery !== null) {
                $this->save($user, $recovery['authenticator']);
            }
        });

        $this->enrollments->forget($factor->key());

        $isRecovery
            ? RecoveryCodesGenerated::dispatch($user, $authenticator)
            : AuthenticatorAdded::dispatch($user, $authenticator);

        if ($recovery !== null) {
            RecoveryCodesGenerated::dispatch($user, $recovery['authenticator']);
        }

        return $this->status('authenticator-added', array_filter([
            'authenticator' => $authenticator->factor()->present($authenticator),
            'recoveryCodes' => $recovery['codes'] ?? null,
        ]));
    }

    public function update(Request $request, string $authenticator): StatusResponse
    {
        $authenticator = $this->find($request, $authenticator);

        $validated = $request->validate([
            'name' => ['sometimes', 'string', 'max:64'],
            // Recovery codes are a fallback, never the way to sign in first.
            'default' => ['sometimes', 'boolean', Rule::prohibitedIf($authenticator->factor === RecoveryCodes::KEY)],
        ]);

        DB::transaction(function () use ($authenticator, $validated) {
            if ($validated['default'] ?? false) {
                $this->keyring->for($authenticator->user())->all()
                    ->filter(fn (Authenticator $other) => $other->exists && $other->is_default)
                    ->each(fn (Authenticator $other) => $other->forceFill(['is_default' => false])->save());
            }

            $authenticator->fill(array_intersect_key($validated, ['name' => true]));

            if (array_key_exists('default', $validated)) {
                $authenticator->is_default = (bool) $validated['default'];
            }

            $authenticator->save();
        });

        return $this->status('authenticator-updated', ['authenticator' => $authenticator->factor()->present($authenticator)]);
    }

    /**
     * Remove an authenticator, unless that would leave the user unable to
     * sign in the way their policy requires.
     */
    public function destroy(Request $request, string $authenticator): StatusResponse
    {
        $user = $request->user();

        // One removal per user at a time, so two at once can't each count on
        // the other's authenticator still being there.
        $removed = RowLock::hold($user, function () use ($request, $user, $authenticator) {
            $authenticator = $this->find($request, $authenticator);
            $remaining = $this->keyring->for($user)->without($authenticator);

            // Recovery codes are only useful while there's a second factor to
            // recover, so they go too when this was the last one. The policy
            // is checked against what will actually be left.
            $onlyRecoveryLeft = $remaining->all()->every(fn (Authenticator $other) => $other->isVirtual() || $other->factor === RecoveryCodes::KEY);
            $cascade = $onlyRecoveryLeft ? $remaining->of(RecoveryCodes::KEY)->all() : [];
            $left = $remaining->without(...$cascade);

            $policy = $this->keyring->policy($user, Attempt::start(Purpose::Login, $user));

            if (! $left->canSignIn() || (! $policy->onlyIfEnrolled && ! $left->canMeet($policy))) {
                throw ValidationException::withMessages(['authenticator' => __('keyring::keyring.last_factor')]);
            }

            collect([$authenticator, ...$cascade])->each->delete();

            return $authenticator;
        });

        AuthenticatorRemoved::dispatch($user, $removed);

        return $this->status('authenticator-removed');
    }

    /**
     * A fresh set of recovery codes to hand out with the first extra factor.
     *
     * @return array{codes: list<string>, authenticator: Authenticator}|null
     */
    protected function recoveryCodes(): ?array
    {
        $factor = $this->keyring->hasFactor(RecoveryCodes::KEY) ? $this->keyring->factor(RecoveryCodes::KEY) : null;

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

    /**
     * The factor to enroll. Until the email address is proven, the account
     * may belong to someone who registered it first, and factors they added
     * would survive the real owner's password reset.
     */
    protected function enrollable(Request $request, string $key): Enrollable
    {
        $user = $request->user();

        abort_if($user instanceof MustVerifyEmail && ! $user->hasVerifiedEmail(), 403, __('keyring::keyring.verify_email_first'));

        $factor = $this->keyring->factor($key);

        return $factor instanceof Enrollable ? $factor : abort(404);
    }

    protected function find(Request $request, string $id): Authenticator
    {
        return $this->keyring->authenticatorModel()::query()
            ->ownedBy($request->user())
            ->findOrFail($id)
            ->setRelation('authenticatable', $request->user());
    }
}
