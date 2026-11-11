<?php

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Keyring\Devices\DeviceManager;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Factors\RecoveryCodes;
use Keyring\KeyringManager;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;
use Keyring\Login\StepUp;
use Keyring\Sessions\SessionAssurance;
use Keyring\Support\Duration;
use Keyring\UserKeyring;
use Symfony\Component\HttpFoundation\Response;

/**
 * Requires the user to have verified within a window, e.g. keyring.fresh:15m,
 * with the strongest combination their account can give, and at least what
 * signing in would ask of them: both factors for a user with two, and the
 * key for a user with one that can't leave its device. Adding a sign-in
 * method takes proving the best the account already has.
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
     * What signing in would ask of this user, the strongest combination
     * their account can give, and a possession factor whenever they have
     * one: otherwise a stolen session plus one phished factor could add new
     * ones without ever touching the rest.
     *
     * The policy is asked twice: about this browser as a sign in would find
     * it, and about one nothing is known of. The stricter answer stands, so
     * a policy that asks more of a new device is heard here, and one that
     * asks less of a trusted device gets no discount.
     */
    protected function requirement(Request $request): Requirement
    {
        $user = $this->keyring->user();
        $keyring = $this->keyring->for($user)->withoutFallbacks();

        $here = Attempt::start(Purpose::Login, $user);
        $here->resolveDevice($this->devices->find($request, $user)?->id);

        $policy = $this->keyring->requirementFor($user, $here, reachable: true)
            ->atLeast($this->keyring->requirementFor($user, Attempt::start(Purpose::Login, $user), reachable: true));

        // Together they must still be something the account can prove, or
        // it could never add anything again.
        $requirement = $keyring->reachable($policy->atLeast($this->strongest($keyring, $policy)));

        return $keyring->has(Category::Possession)
            ? $requirement->atLeast(Requirement::aal1()->including(Category::Possession))
            : $requirement;
    }

    /**
     * The most the account's authenticators can prove together, whatever
     * the policy asks at sign in. NIST SP 800-63B-4 (Sec. 4.1.2.1) has a new
     * authenticator bound at the highest level the account can reach, or a
     * user who holds a key that can't leave its device could add another
     * after proving only a password and a code.
     *
     * A key nothing vouches for is asked for too: if it is what it says, it
     * is the best the account has. A recovery code is taken in a lost key's
     * place, as it is at sign in, unless the policy takes none there. An
     * account with nothing beyond one factor proves that, so it can always
     * add its first.
     */
    protected function strongest(UserKeyring $keyring, Requirement $policy): Requirement
    {
        $strongest = array_find([Requirement::aal3(), Requirement::aal2()->deviceBound()], $keyring->canMeet(...));

        return $strongest?->acceptingInstead($policy->noDowngrade ? $policy->downgradeExceptions : [RecoveryCodes::KEY])
            ?? $keyring->reachable(Requirement::aal2());
    }
}
