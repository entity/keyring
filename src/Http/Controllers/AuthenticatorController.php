<?php

namespace Keyring\Http\Controllers;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use Keyring\Contracts\Enrollable;
use Keyring\Enrollment\EnrollmentStore;
use Keyring\Enums\Purpose;
use Keyring\Events\AuthenticatorAdded;
use Keyring\Events\AuthenticatorRemoved;
use Keyring\Events\RecoveryCodesGenerated;
use Keyring\Factors\RecoveryCodes;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\KeyringManager;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use Keyring\UserKeyring;

/**
 * Adding, renaming, choosing the default and removing authenticators. One
 * set of routes for every factor.
 */
class AuthenticatorController
{
    use ChoosesFormat;

    public function __construct(
        protected KeyringManager $keyring,
        protected EnrollmentStore $enrollments,
    ) {}

    /**
     * Begin enrolling: returns what the user needs to see (QR code, codes...).
     */
    public function store(Request $request, string $factor): mixed
    {
        $this->ensureEmailVerified($request);
        $factor = $this->enrollable($factor);
        $enrollment = $factor->beginEnrollment($request->user(), $request);

        $this->enrollments->put($enrollment);

        return $this->respond($request, ['factor' => $factor->key(), 'enrollment' => $enrollment->props], 'enrollment-started');
    }

    /**
     * Finish enrolling once the user proves it works.
     */
    public function confirm(Request $request, string $factor): mixed
    {
        $this->ensureEmailVerified($request);
        $factor = $this->enrollable($factor);
        $user = $request->user();

        $enrollment = $this->enrollments->get($factor->key())
            ?? throw ValidationException::withMessages(['code' => __('keyring::keyring.enrollment_expired')]);

        $request->validate($factor->enrollmentRules());

        $authenticator = $factor->confirmEnrollment($user, $enrollment, $request)
            ?? throw ValidationException::withMessages(['code' => __('keyring::keyring.invalid')]);

        $recoveryCodes = DB::transaction(function () use ($factor, $user, $authenticator) {
            $keyring = $this->keyring->for($user);

            if (! $factor->multiple()) {
                $keyring->of($factor->key())->each->delete();
            }

            $authenticator->authenticatable()->associate($user);
            $authenticator->forceFill([
                'confirmed_at' => now(),
                'is_default' => $keyring->default() === null && $factor->key() !== 'recovery',
            ])->save();

            return $this->offerRecoveryCodes($user, $factor, $keyring->of('recovery')->isEmpty());
        });

        $this->enrollments->forget($factor->key());

        $authenticator->factor === 'recovery'
            ? RecoveryCodesGenerated::dispatch($user, $authenticator)
            : AuthenticatorAdded::dispatch($user, $authenticator);

        return $this->respond($request, array_filter([
            'authenticator' => $authenticator->factor()->present($authenticator),
            'recoveryCodes' => $recoveryCodes,
        ]), 'authenticator-added');
    }

    public function update(Request $request, string $authenticator): mixed
    {
        $authenticator = $this->find($request, $authenticator);

        $validated = $request->validate([
            'name' => ['sometimes', 'string', 'max:64'],
            'default' => ['sometimes', 'boolean'],
        ]);

        DB::transaction(function () use ($authenticator, $validated) {
            if ($validated['default'] ?? false) {
                $this->keyring->for($authenticator->user())->all()
                    ->filter(fn (Authenticator $other) => $other->exists && $other->is_default)
                    ->each(fn (Authenticator $other) => $other->forceFill(['is_default' => false])->save());
            }

            $authenticator->forceFill(array_filter([
                'name' => $validated['name'] ?? null,
                'is_default' => ($validated['default'] ?? null) === null ? null : (bool) $validated['default'],
            ], fn ($value) => $value !== null))->save();
        });

        return $this->respond($request, ['authenticator' => $authenticator->factor()->present($authenticator)], 'authenticator-updated');
    }

    /**
     * Remove an authenticator, unless that would leave the user unable to
     * sign in the way their policy requires.
     */
    public function destroy(Request $request, string $authenticator): mixed
    {
        $authenticator = $this->find($request, $authenticator);
        $user = $request->user();
        $remaining = $this->keyring->for($user)->without($authenticator);

        // Recovery codes are only useful while there's a second factor to
        // recover, so they go too when this was the last one. Check the policy
        // against what will actually be left.
        $others = $remaining->all()->reject(fn (Authenticator $other) => $other->isVirtual() || $other->factor === 'recovery');
        $cascade = $others->isEmpty() ? $remaining->of('recovery') : new Collection;
        $left = $cascade->reduce(fn (UserKeyring $keyring, Authenticator $recovery) => $keyring->without($recovery), $remaining);

        $policy = $this->keyring->policy($user, Attempt::start(Purpose::Login, $user));

        if (! $left->canSignIn() || (! $policy->onlyIfEnrolled && ! $left->canMeet($policy))) {
            throw ValidationException::withMessages(['authenticator' => __('keyring::keyring.last_factor')]);
        }

        DB::transaction(function () use ($authenticator, $cascade) {
            $authenticator->delete();
            $cascade->each->delete();
        });

        AuthenticatorRemoved::dispatch($user, $authenticator);

        return $this->respond($request, [], 'authenticator-removed');
    }

    /**
     * After the first extra factor, hand out recovery codes automatically.
     *
     * @return list<string>|null
     */
    protected function offerRecoveryCodes(mixed $user, Enrollable $factor, bool $hasNone): ?array
    {
        if ($factor->key() === 'recovery' || ! $hasNone || ! $this->keyring->hasFactor('recovery')) {
            return null;
        }

        $recovery = $this->keyring->factor('recovery');

        if (! $recovery instanceof RecoveryCodes) {
            return null;
        }

        ['codes' => $codes, 'secret' => $secret] = $recovery->generate();

        $authenticator = $recovery->make($secret);
        $authenticator->authenticatable()->associate($user);
        $authenticator->forceFill(['confirmed_at' => now()])->save();

        RecoveryCodesGenerated::dispatch($user, $authenticator);

        return $codes;
    }

    /**
     * Until the email address is proven, the account may belong to someone
     * who registered it first. Factors added then would survive the real
     * owner's password reset.
     */
    protected function ensureEmailVerified(Request $request): void
    {
        $user = $request->user();

        if ($user instanceof MustVerifyEmail && ! $user->hasVerifiedEmail()) {
            abort(403, __('keyring::keyring.verify_email_first'));
        }
    }

    protected function enrollable(string $key): Enrollable
    {
        $factor = $this->keyring->hasFactor($key) ? $this->keyring->factor($key) : null;

        return $factor instanceof Enrollable ? $factor : abort(404);
    }

    protected function find(Request $request, string $id): Authenticator
    {
        return $this->keyring->authenticatorModel()::query()
            ->whereMorphedTo('authenticatable', $request->user())
            ->findOrFail($id)
            ->setRelation('authenticatable', $request->user());
    }

    /**
     * @param  array<string, mixed>  $data
     */
    protected function respond(Request $request, array $data, string $status): mixed
    {
        if ($this->wantsJson($request)) {
            return new JsonResponse(['status' => $status, ...$data]);
        }

        // Under keyring.result: flashing "keyring" itself would replace the
        // session's verifications and registry ID, which live under keyring.*.
        return back()->with('status', $status)->with('keyring.result', $data);
    }
}
