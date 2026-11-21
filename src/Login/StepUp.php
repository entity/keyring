<?php

declare(strict_types=1);

namespace Keyring\Login;

use Illuminate\Http\Request;
use Keyring\Contracts\Responses\ConfirmationRequiredResponse;
use Keyring\Contracts\Responses\EnrollmentRequiredResponse;
use Keyring\Enums\Purpose;
use Keyring\KeyringManager;
use Keyring\Sessions\SessionAssurance;
use Symfony\Component\HttpFoundation\Response;

/**
 * Sends a signed-in user to prove something again before continuing.
 */
class StepUp
{
    public function __construct(
        protected AttemptStore $attempts,
        protected SessionAssurance $assurance,
        protected KeyringManager $keyring,
        protected Detours $detours,
    ) {}

    /**
     * @param  list<Verification>  $proved  what still counts from this session, to build on
     *                                      (raising assurance), or nothing to ask afresh
     */
    public function require(Request $request, Requirement $requirement, array $proved = []): Response
    {
        // Without the sign-in methods to meet it, confirming can't help, and
        // would only send the user round in a loop.
        if (! $this->keyring->for($this->keyring->user())->canMeet($requirement)) {
            return $this->enrollFirst($request);
        }

        $this->begin($request, $requirement, $proved);

        return $this->keyring->response(ConfirmationRequiredResponse::class)->toResponse($request);
    }

    /**
     * Send a user who hasn't set up what's needed to keyring.enrollment_url,
     * or answer 403 when there isn't one. Where they were going is saved,
     * for the enrollment to hand back as "continue".
     *
     * @param  string|null  $continue  where to carry on to instead of this
     *                                 page, for one of Keyring's own pages
     *                                 that was there on another's behalf
     */
    public function enrollFirst(Request $request, ?string $continue = null): Response
    {
        $this->detours->save($request, Detours::ENROLLMENT, $continue);

        return $this->keyring->response(EnrollmentRequiredResponse::class)->toResponse($request);
    }

    /**
     * Start a confirm attempt, or carry on with the one in progress when it's
     * for the same requirement, so a page that asks again halfway through
     * doesn't lose what the user already proved.
     *
     * @param  list<Verification>  $proved
     */
    public function begin(Request $request, Requirement $requirement, array $proved = []): Attempt
    {
        $current = $this->attempts->current(Purpose::Confirm);

        if ($current?->requirement?->toArray() === $requirement->toArray()) {
            return $current;
        }

        return $this->attempts->start(
            Purpose::Confirm,
            $this->keyring->user(),
            requirement: $requirement,
            verifications: $proved,
        );
    }
}
