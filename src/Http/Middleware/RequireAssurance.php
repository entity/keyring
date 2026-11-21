<?php

declare(strict_types=1);

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Keyring\Enums\Assurance;
use Keyring\Login\Requirement;
use Keyring\Login\StepUp;
use Symfony\Component\HttpFoundation\Response;

/**
 * Requires the session to have reached an assurance level, e.g. keyring:aal2.
 * Users who signed in with less are asked for whatever is missing. More can
 * be asked of the level by name: keyring:aal2,device-bound wants a key that
 * can't leave its device among what was proved, attested or not.
 */
class RequireAssurance
{
    public function __construct(
        protected StepUp $stepUp,
    ) {}

    public function handle(Request $request, Closure $next, string $level = 'aal2', string ...$also): Response
    {
        $requirement = Requirement::named($level, ...$also);

        return $this->stepUp->unlessReached($request, Assurance::fromName($level), $requirement)
            ?? $next($request);
    }
}
