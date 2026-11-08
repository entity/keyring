<?php

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Keyring\Login\Requirement;
use Keyring\Login\StepUp;
use Keyring\Session\SessionAssurance;
use Keyring\Support\Duration;
use Symfony\Component\HttpFoundation\Response;

/**
 * Requires a verification within a window, e.g. keyring.fresh:15m. Any
 * enrolled factor counts. The window is fixed from the moment of verification
 * and doesn't slide with activity.
 */
class RequireFreshVerification
{
    public function __construct(
        protected SessionAssurance $assurance,
        protected StepUp $stepUp,
    ) {}

    public function handle(Request $request, Closure $next, string $window = '15m'): Response
    {
        $since = now()->getTimestamp() - Duration::seconds($window);

        if (($this->assurance->lastVerifiedAt() ?? 0) >= $since) {
            return $next($request);
        }

        return $this->stepUp->require($request, Requirement::aal1(), building: false);
    }
}
