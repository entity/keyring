<?php

declare(strict_types=1);

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
 * Users who signed in with less are asked for whatever is missing. More can
 * be asked of the level by name: keyring:aal2,device-bound wants a key that
 * can't leave its device among what was proved, attested or not.
 */
class RequireAssurance
{
    public function __construct(
        protected SessionAssurance $assurance,
        protected StepUp $stepUp,
    ) {}

    public function handle(Request $request, Closure $next, string $level = 'aal2', string ...$also): Response
    {
        $requirement = Requirement::named($level, ...$also);
        $level = Assurance::fromName($level);
        $proved = $this->assurance->countingToward($level);

        if ($this->assurance->level()->atLeast($level) && $requirement->isMetBy($proved)) {
            return $next($request);
        }

        return $this->stepUp->require($request, $requirement, $proved);
    }
}
