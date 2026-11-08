<?php

namespace Keyring\Login;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Keyring\Enums\Purpose;
use Keyring\Session\SessionAssurance;
use Symfony\Component\HttpFoundation\Response;

/**
 * Sends a signed-in user to prove something again before continuing.
 */
class StepUp
{
    public function __construct(
        protected AttemptStore $attempts,
        protected SessionAssurance $assurance,
    ) {}

    /**
     * @param  bool  $building  count what the user already proved this session (raising assurance),
     *                          rather than asking for a fresh verification
     */
    public function require(Request $request, Requirement $requirement, bool $building): Response
    {
        $this->begin($request, $requirement, $building);

        $url = route('keyring.confirm.challenge');

        if ($request->expectsJson() && ! $request->hasHeader('X-Inertia')) {
            return new JsonResponse(['message' => __('keyring::keyring.confirm'), 'redirect' => $url], 423);
        }

        return redirect()->guest($url);
    }

    public function begin(Request $request, Requirement $requirement, bool $building): Attempt
    {
        return $this->attempts->start(
            Purpose::Confirm,
            $request->user(),
            requirement: $requirement,
            verifications: $building ? $this->assurance->all() : [],
        );
    }
}
