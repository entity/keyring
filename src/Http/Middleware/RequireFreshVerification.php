<?php

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Keyring\Enums\Category;
use Keyring\KeyringManager;
use Keyring\Login\Requirement;
use Keyring\Login\StepUp;
use Keyring\Sessions\SessionAssurance;
use Keyring\Support\Duration;
use Symfony\Component\HttpFoundation\Response;

/**
 * Requires a verification within a window, e.g. keyring.fresh:15m. Users
 * with only a password confirm with it; users with a second factor must use
 * one. The window is fixed from the moment of verification and doesn't slide
 * with activity.
 */
class RequireFreshVerification
{
    public function __construct(
        protected SessionAssurance $assurance,
        protected StepUp $stepUp,
        protected KeyringManager $keyring,
    ) {}

    public function handle(Request $request, Closure $next, string $window = '15m'): Response
    {
        $since = now()->getTimestamp() - Duration::seconds($window);
        $requirement = $this->requirement($request);

        if ($requirement->isMetBy($this->assurance->since($since))) {
            return $next($request);
        }

        return $this->stepUp->require($request, $requirement, building: false);
    }

    /**
     * Users who have something beyond a password must use it: otherwise a
     * stolen session plus a phished password could add new factors without
     * ever touching the existing ones.
     */
    protected function requirement(Request $request): Requirement
    {
        $user = $request->user();

        return $user !== null && $this->keyring->for($user)->has(Category::Possession)
            ? Requirement::aal1()->including(Category::Possession)
            : Requirement::aal1();
    }
}
