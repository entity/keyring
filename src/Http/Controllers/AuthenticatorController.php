<?php

namespace Keyring\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Keyring\Changes\AuthenticatorChanges;
use Keyring\Contracts\Enrollable;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Contracts\SendsCodes;
use Keyring\Enrollment\Enrollment;
use Keyring\Enrollment\EnrollmentStore;
use Keyring\Events\EnrollmentRefused;
use Keyring\Factors\RecoveryCodes;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Models\Authenticator;
use Keyring\Support\Input;
use Keyring\Support\Throttle;

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
        protected AuthenticatorChanges $changes,
        protected Throttle $throttle,
    ) {}

    /**
     * Begin enrolling: returns what the user needs to see (QR code, codes...).
     */
    public function store(Request $request, string $factor): StatusResponse
    {
        $factor = $this->enrollable($request, $factor);

        // Enrolling a code factor sends a code, wherever the user asks for it to go.
        if ($factor instanceof SendsCodes) {
            $this->throttle->sending($factor->key(), $this->keyring->user()->getAuthIdentifier());
        }

        $enrollment = $factor->beginEnrollment($this->keyring->user(), $request);

        $this->enrollments->put($enrollment);

        return $this->status('enrollment-started', ['factor' => $factor->key(), 'enrollment' => $enrollment->props]);
    }

    /**
     * Finish enrolling once the user proves it works.
     */
    public function confirm(Request $request, string $factor): StatusResponse
    {
        $factor = $this->enrollable($request, $factor);

        $enrollment = $this->enrollments->get($factor->key())
            ?? throw ValidationException::withMessages([$factor->errorKey() => __('keyring::keyring.enrollment_expired')]);

        Input::validate($request, $factor->enrollmentRules());

        $authenticator = $this->confirmed($factor, $enrollment, $request);

        // Each enrollment adds its authenticator once, whichever copy of the
        // session it comes back in.
        if (! $this->enrollments->claim($enrollment)) {
            throw ValidationException::withMessages([$factor->errorKey() => __('keyring::keyring.enrollment_expired')]);
        }

        $recoveryCodes = $this->changes->add($this->keyring->user(), $factor, $authenticator);

        $this->enrollments->forget($factor->key());

        return $this->status('authenticator-added', array_filter([
            'authenticator' => $authenticator->factor()->present($authenticator),
            'recoveryCodes' => $recoveryCodes,
        ]));
    }

    public function update(Request $request, string $authenticator): StatusResponse
    {
        $authenticator = $this->changes->find($this->keyring->user(), $authenticator);

        $changes = $request->validate([
            'name' => ['sometimes', 'string', 'max:64'],
            // Recovery codes are a fallback, never the way to sign in first.
            'default' => ['sometimes', 'boolean', Rule::prohibitedIf($authenticator->factor === RecoveryCodes::KEY)],
        ]);

        $this->changes->update($authenticator, [
            ...Arr::only($changes, 'name'),
            ...$request->has('default') ? ['default' => $request->boolean('default')] : [],
        ]);

        return $this->status('authenticator-updated', ['authenticator' => $authenticator->factor()->present($authenticator)]);
    }

    public function destroy(Request $request, string $authenticator): StatusResponse
    {
        // Only asked for when this is the last second factor.
        Input::validate($request, ['password' => ['nullable', 'string']]);

        $this->changes->remove($this->keyring->user(), $authenticator, Input::get($request, 'password'));

        return $this->status('authenticator-removed');
    }

    /**
     * The authenticator the user just proved works. A proof the factor
     * turns down is answered as before and goes on record, whether the
     * factor says no or throws its own message.
     *
     * @throws ValidationException
     */
    protected function confirmed(Enrollable $factor, Enrollment $enrollment, Request $request): Authenticator
    {
        try {
            return $factor->confirmEnrollment($this->keyring->user(), $enrollment, $request)
                ?? throw ValidationException::withMessages([$factor->errorKey() => __('keyring::keyring.invalid')]);
        } catch (ValidationException $e) {
            EnrollmentRefused::dispatch($this->keyring->user(), $factor->key(), 'invalid');

            throw $e;
        }
    }

    /**
     * The factor to enroll. Until the email address is proven, the account
     * may belong to someone who registered it first, and factors they added
     * would survive the real owner's password reset.
     */
    protected function enrollable(Request $request, string $key): Enrollable
    {
        if (! $this->keyring->allowsEnrollment($this->keyring->user())) {
            EnrollmentRefused::dispatch($this->keyring->user(), $key, 'not_allowed');

            abort(403, __('keyring::keyring.verify_email_first'));
        }

        $factor = $this->keyring->factor($key);

        return $factor instanceof Enrollable ? $factor : abort(404);
    }
}
