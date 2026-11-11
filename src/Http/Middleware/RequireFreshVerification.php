<?php

declare(strict_types=1);

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Keyring\Devices\DeviceManager;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\KeyringManager;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;
use Keyring\Login\StepUp;
use Keyring\Sessions\SessionAssurance;
use Keyring\Support\Duration;
use Symfony\Component\HttpFoundation\Response;

/**
 * Requires the user to have verified within a window, e.g. keyring.fresh:15m,
 * as much as signing in would ask of them, as far as they can: both factors
 * for a user with two, so adding a sign-in method takes proving the ones the
 * account already has.
 * Users with a possession factor always use one. The window is fixed from the
 * moment of verification and doesn't slide with activity.
 */
class RequireFreshVerification
{
    public function __construct(
        protected SessionAssurance $assurance,
        protected StepUp $stepUp,
        protected KeyringManager $keyring,
        protected DeviceManager $devices,
    ) {}

    public function handle(Request $request, Closure $next, string $window = '15m'): Response
    {
        $since = now()->getTimestamp() - Duration::seconds($window);
        $requirement = $this->requirement($request);

        if ($requirement->isMetBy($this->assurance->since($since))) {
            return $next($request);
        }

        return $this->stepUp->require($request, $requirement);
    }

    /**
     * What signing in would ask of this user, and a possession factor
     * whenever they have one: otherwise a stolen session plus one phished
     * factor could add new ones without ever touching the rest.
     *
     * The policy is asked twice: about this browser as a sign in would find
     * it, and about one nothing is known of. The stricter answer stands, so
     * a policy that asks more of a new device is heard here, and one that
     * asks less of a trusted device gets no discount.
     */
    protected function requirement(Request $request): Requirement
    {
        $user = $this->keyring->user();

        $here = Attempt::start(Purpose::Login, $user);
        $here->resolveDevice($this->devices->find($request, $user)?->id);

        $requirement = $this->keyring->requirementFor($user, $here, reachable: true)
            ->atLeast($this->keyring->requirementFor($user, Attempt::start(Purpose::Login, $user), reachable: true));

        return $this->keyring->for($user)->has(Category::Possession)
            ? $requirement->atLeast(Requirement::aal1()->including(Category::Possession))
            : $requirement;
    }
}
