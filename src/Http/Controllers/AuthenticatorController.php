<?php

namespace Keyring\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Keyring\Changes\AuthenticatorChanges;
use Keyring\Contracts\Enrollable;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Contracts\SendsCodes;
use Keyring\Enrollment\EnrollmentStore;
use Keyring\Factors\RecoveryCodes;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
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
    ) {}

    /**
     * Begin enrolling: returns what the user needs to see (QR code, codes...).
     */
    public function store(Request $request, string $factor): StatusResponse
    {
        $factor = $this->enrollable($request, $factor);

        // Enrolling a code factor sends a code, wherever the user asks for it to go.
        if ($factor instanceof SendsCodes) {
            Throttle::sending($factor->key(), $request->user()->getAuthIdentifier());
        }

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

        $enrollment = $this->enrollments->get($factor->key())
            ?? throw ValidationException::withMessages([$factor->errorKey() => __('keyring::keyring.enrollment_expired')]);

        $request->validate($factor->enrollmentRules());

        $authenticator = $factor->confirmEnrollment($request->user(), $enrollment, $request)
            ?? throw ValidationException::withMessages([$factor->errorKey() => __('keyring::keyring.invalid')]);

        $recoveryCodes = $this->changes->add($request->user(), $factor, $authenticator);

        $this->enrollments->forget($factor->key());

        return $this->status('authenticator-added', array_filter([
            'authenticator' => $authenticator->factor()->present($authenticator),
            'recoveryCodes' => $recoveryCodes,
        ]));
    }

    public function update(Request $request, string $authenticator): StatusResponse
    {
        $authenticator = $this->changes->find($request->user(), $authenticator);

        $this->changes->update($authenticator, $request->validate([
            'name' => ['sometimes', 'string', 'max:64'],
            // Recovery codes are a fallback, never the way to sign in first.
            'default' => ['sometimes', 'boolean', Rule::prohibitedIf($authenticator->factor === RecoveryCodes::KEY)],
        ]));

        return $this->status('authenticator-updated', ['authenticator' => $authenticator->factor()->present($authenticator)]);
    }

    public function destroy(Request $request, string $authenticator): StatusResponse
    {
        // Only asked for when this is the last second factor.
        $request->validate(['password' => ['nullable', 'string']]);

        $this->changes->remove($request->user(), $authenticator, $request->input('password'));

        return $this->status('authenticator-removed');
    }

    /**
     * The factor to enroll. Until the email address is proven, the account
     * may belong to someone who registered it first, and factors they added
     * would survive the real owner's password reset.
     */
    protected function enrollable(Request $request, string $key): Enrollable
    {
        abort_unless($this->keyring->allowsEnrollment($request->user()), 403, __('keyring::keyring.verify_email_first'));

        $factor = $this->keyring->factor($key);

        return $factor instanceof Enrollable ? $factor : abort(404);
    }
}
