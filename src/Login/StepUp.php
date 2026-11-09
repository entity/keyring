<?php

namespace Keyring\Login;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Keyring\Enums\Purpose;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\KeyringManager;
use Keyring\Sessions\SessionAssurance;
use Symfony\Component\HttpFoundation\Response;

/**
 * Sends a signed-in user to prove something again before continuing.
 */
class StepUp
{
    use ChoosesFormat;

    public function __construct(
        protected AttemptStore $attempts,
        protected SessionAssurance $assurance,
        protected KeyringManager $keyring,
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

        $url = route('keyring.confirm.challenge');

        if ($this->wantsJson($request)) {
            // Come back to the page that made the call once confirmed.
            redirect()->setIntendedUrl(url()->previous());

            return new JsonResponse(['message' => __('keyring::keyring.confirm'), 'redirect' => $url], 423);
        }

        return redirect()->guest($url);
    }

    /**
     * Send a user who hasn't set up what's needed to keyring.enrollment_url,
     * or answer 403 when there isn't one.
     */
    public function enrollFirst(Request $request): Response
    {
        $url = config('keyring.enrollment_url');
        $message = $this->keyring->statusMessage('enroll-first');

        if ($this->wantsJson($request)) {
            return new JsonResponse(['status' => 'enroll-first', 'message' => $message, 'redirect' => $url], 403);
        }

        abort_if($url === null, 403, $message);

        return redirect($url)->with('status', 'enroll-first');
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
