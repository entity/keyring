<?php

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Keyring\Enums\Assurance;
use Keyring\KeyringManager;
use Keyring\Login\Requirement;
use Keyring\Login\StepUp;
use Symfony\Component\HttpFoundation\Response;

/**
 * Users must have set up what a level needs before going further, e.g.
 * keyring.enrolled (AAL2) on the whole app: they sign in with what they have,
 * then add a second factor. Recovery codes and email codes
 * don't count. Users who haven't are sent to keyring.enrollment_url. Guests
 * are let through, so it can sit in the web group and leave them to auth.
 */
class RequireEnrollment
{
    /**
     * Routes users still need: Keyring's own (enrolling, confirming, devices),
     * signing out, verifying their email and changing their password.
     *
     * @var list<string>
     */
    protected array $except = ['keyring.*', 'logout', 'verification.*', 'user-password.update'];

    public function __construct(
        protected KeyringManager $keyring,
        protected StepUp $stepUp,
    ) {}

    public function handle(Request $request, Closure $next, string $level = 'aal2'): Response
    {
        $requirement = Requirement::for(Assurance::fromName($level));
        $url = config('keyring.enrollment_url');

        $user = $this->keyring->guard()->user();

        if (! $user instanceof Model || $this->isExcepted($request, $url) || $this->keyring->for($user)->withoutFallbacks()->canMeet($requirement)) {
            return $next($request);
        }

        return $this->stepUp->enrollFirst($request);
    }

    /**
     * The page they're sent to is always let through too, so it can't send
     * them round in a loop.
     */
    protected function isExcepted(Request $request, ?string $url): bool
    {
        return $request->routeIs(...$this->except, ...config('keyring.enrollment_except'))
            || ($url !== null && $request->is(trim((string) parse_url($url, PHP_URL_PATH), '/') ?: '/'));
    }
}
