<?php

declare(strict_types=1);

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Keyring\Login\StepUp;
use Keyring\Support\Duration;
use Symfony\Component\HttpFoundation\Response;

/**
 * Requires the user to have verified within a window, e.g. keyring.fresh:15m,
 * with the strongest combination their account can give, and at least what
 * signing in would ask of them: both factors for a user with two, and the
 * key for a user with one that can't leave its device. Adding a sign-in
 * method takes proving the best the account already has.
 * Users with a possession factor always use one, and a recovery code only
 * counts beside another factor. The window is fixed from the moment of
 * verification and doesn't slide with activity. StepUp::freshRequirement()
 * says what's asked.
 */
class RequireFreshVerification
{
    public function __construct(
        protected StepUp $stepUp,
    ) {}

    public function handle(Request $request, Closure $next, string $window = '15m'): Response
    {
        return $this->stepUp->unlessFresh($request, now()->getTimestamp() - Duration::seconds($window))
            ?? $next($request);
    }
}
