<?php

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Keyring\Enums\Assurance;
use Keyring\Login\Requirement;
use Keyring\Login\StepUp;
use Keyring\Sessions\SessionAssurance;
use Symfony\Component\HttpFoundation\Response;

/**
 * Requires the session to have reached an assurance level, e.g. keyring:aal2.
 * Users who signed in with less are asked for whatever is missing.
 */
class RequireAssurance
{
    public function __construct(
        protected SessionAssurance $assurance,
        protected StepUp $stepUp,
    ) {}

    public function handle(Request $request, Closure $next, string $level = 'aal2'): Response
    {
        $level = Assurance::fromName($level);

        if ($this->assurance->level()->atLeast($level)) {
            return $next($request);
        }

        return $this->stepUp->require($request, Requirement::for($level), building: true);
    }
}
