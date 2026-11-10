<?php

namespace Keyring;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Inertia\ComponentNotFoundException;
use Inertia\ResponseFactory;
use InvalidArgumentException;
use Keyring\Activity\SecurityLog;
use Keyring\Changes\ProtectedAttributes;
use Keyring\Concerns\HasKeyring;
use Keyring\Contracts\CreatesNewUsers;
use Keyring\Contracts\Factor;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Contracts\ResetsUserPasswords;
use Keyring\Contracts\UpdatesUserPasswords;
use Keyring\Contracts\ValidatesEmailChanges;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Exceptions\EmailVerificationRequired;
use Keyring\Exceptions\MissingNotification;
use Keyring\Exceptions\MissingPage;
use Keyring\Exceptions\MissingTrait;
use Keyring\Factors\FactorRegistry;
use Keyring\Factors\RecoveryCodes;
use Keyring\Login\Attempt;
use Keyring\Login\AttemptStore;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
use Keyring\Models\PendingChange;
use Keyring\Models\SecurityEvent;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Steps;
use Keyring\Pipeline\Verifier;
use Keyring\Risk\RiskEngine;
use Keyring\Support\Url;
use Keyring\Testing\KeyringFake;
use LogicException;
use Symfony\Component\HttpFoundation\Response;

class KeyringManager
{
    /**
     * Every notification Keyring can send: the security notices, which are
     * only sent once the app registers one, then the emails a flow needs.
     */
    public const array NOTIFICATIONS = [
        'new_device', 'password_changed', 'authenticator_added', 'authenticator_removed',
        'second_factor_failed', 'recovery_code_used', 'suspicious_activity', 'clone_suspected',
        'email_changed', 'email_change_reverted',
        'verification_code', 'confirm_email_change', 'email_change_notice', 'email_address_in_use',
    ];

    /** @var Closure(Authenticatable&Model, Attempt): Requirement|Requirement */
    protected Closure|Requirement $policy;

    /** @var array<string, string|Closure(array<string, mixed>): mixed> */
    protected array $pages = [];

    /** @var list<Closure(Steps): (Steps|null)> */
    protected array $pipelineCallbacks = [];

    /** @var class-string<Authenticator> */
    protected string $authenticatorModel = Authenticator::class;

    /** @var class-string<Device> */
    protected string $deviceModel = Device::class;

    /** @var class-string<PendingChange> */
    protected string $pendingChangeModel = PendingChange::class;

    /** @var class-string<SecurityEvent> */
    protected string $securityEventModel = SecurityEvent::class;

    /** @var (Closure(string): string)|null */
    protected ?Closure $usernameNormalizer = null;

    /** @var (Closure(Request): ((Authenticatable&Model)|null))|null */
    protected ?Closure $userFinder = null;

    /** @var bool|(Closure(Authenticatable&Model, Request): bool) */
    protected bool|Closure $signInAfterRegistering = true;

    /** @var (Closure(Authenticatable&Model): bool)|null */
    protected ?Closure $enrollmentGate = null;

    /** @var (Closure(Request): (string|null))|null */
    protected ?Closure $ipRecorder = null;

    /** @var array<string, class-string<Notification>> The app's notification for each type it sends. */
    protected array $notifications = [];

    /** @var array<class-string, bool> Whether each user model has the HasKeyring trait. */
    protected array $usesKeyring = [];

    public function __construct(
        protected Container $container,
        protected FactorRegistry $factors,
        protected ProtectedAttributes $protection,
    ) {
        $this->policy = Requirement::aal2()->ifEnrolled();
    }

    /**
     * Set the factors users may sign in with.
     *
     * @param  list<class-string<Factor>|Factor|Closure(Container): Factor>  $factors
     */
    public function factors(array $factors): static
    {
        $this->factors->set($factors);

        return $this;
    }

    /**
     * Register a custom factor.
     *
     * @param  Closure(Container): Factor  $resolver
     */
    public function extend(string $key, Closure $resolver): static
    {
        $this->factors->extend($key, $resolver);

        return $this;
    }

    public function factor(string $key): Factor
    {
        return $this->factors->get($key);
    }

    public function hasFactor(string $key): bool
    {
        return $this->factors->has($key);
    }

    /**
     * @return Collection<string, Factor>
     */
    public function registered(): Collection
    {
        return $this->factors->all();
    }

    /**
     * Decide what users must prove to sign in.
     *
     * @param  Closure(Authenticatable&Model, Attempt): Requirement|Requirement  $policy
     */
    public function require(Closure|Requirement $policy): static
    {
        $this->policy = $policy;

        return $this;
    }

    /**
     * What the policy asks of this user, before considering what they've enrolled.
     */
    public function policy(Authenticatable&Model $user, Attempt $attempt): Requirement
    {
        return $this->policy instanceof Closure
            ? ($this->policy)($user, $attempt)
            : $this->policy;
    }

    /**
     * What this user must prove to complete the attempt. With $reachable, a
     * policy they can't fully meet is limited to what they can, as if it said
     * ifEnrolled(): for checks like re-verifying before adding the very key a
     * policy asks for.
     */
    public function requirementFor(Authenticatable&Model $user, Attempt $attempt, bool $reachable = false): Requirement
    {
        $requirement = $this->policy($user, $attempt);

        if ($reachable) {
            $requirement = $requirement->ifEnrolled();
        }

        if ($requirement->noDowngrade && ! $requirement->requiresPhishingResistance
            && $attempt->keyring()->canMeet(Requirement::aal1()->phishingResistant())) {
            $requirement = $requirement->withoutDowngrades();
        }

        if ($requirement->onlyIfEnrolled && ! $attempt->keyring()->canMeet($requirement)) {
            // Recovery codes alone aren't a second factor: asking for them
            // here would spend one on every login.
            $keyring = $attempt->keyring()->without(...$attempt->keyring()->of(RecoveryCodes::KEY)->all());

            return $requirement->limitedTo(
                array_values(array_filter(Category::cases(), $keyring->has(...))),
                $keyring->canMeet(Requirement::aal1()->phishingResistant()),
                $keyring->canMeet(Requirement::aal1()->deviceBound()),
            );
        }

        return $requirement;
    }

    /**
     * Use a different Inertia component (or a closure) for one of Keyring's pages.
     *
     * @param  string|Closure(array<string, mixed>): mixed  $component
     */
    public function page(string $name, string|Closure $component): static
    {
        $this->pages[$name] = $component;

        return $this;
    }

    /**
     * Render one of Keyring's pages: Inertia when installed, Blade otherwise.
     *
     * @param  array<string, mixed>  $props
     */
    public function render(string $name, array $props = []): mixed
    {
        $component = $this->pages[$name] ?? 'auth/'.$name;

        if ($component instanceof Closure) {
            return $component($props);
        }

        if (class_exists(ResponseFactory::class)) {
            try {
                return resolve(ResponseFactory::class)->render($component, $props);
            } catch (ComponentNotFoundException) {
                throw MissingPage::forInertia($name, $component, array_keys($props));
            }
        }

        $view = str_replace('/', '.', $component);

        throw_unless(view()->exists($view), MissingPage::forBlade($name, $view, array_keys($props)));

        return view($view, $props);
    }

    /**
     * Register Keyring's routes. Keyring does this itself unless the "routes"
     * option is false; then call it wherever you like, e.g. inside your own
     * route group with a prefix or extra middleware.
     */
    public function routes(): void
    {
        Route::middleware(config('keyring.middleware'))
            ->group(__DIR__.'/../routes/keyring.php');
    }

    /**
     * Change the steps a verification goes through.
     *
     * @param  Closure(Steps): (Steps|null)  $callback
     */
    public function pipeline(Closure $callback): static
    {
        $known = $this->customisedSteps()->dangerouslyChanged();

        $this->pipelineCallbacks[] = $callback;

        // Run it now, so a refused change stops the app at boot rather than
        // at the first sign in.
        foreach (array_diff($this->customisedSteps()->dangerouslyChanged(), $known) as $step) {
            Log::warning("Keyring's [{$step}] pipeline step was dangerously removed or replaced, so the security check it performs is off.");
        }

        return $this;
    }

    /**
     * @return list<class-string>
     */
    public function steps(): array
    {
        return $this->customisedSteps()->all();
    }

    /**
     * The steps taken out with dangerouslyReplace() or dangerouslyRemove().
     *
     * @return list<class-string>
     */
    public function dangerouslyChangedSteps(): array
    {
        return $this->customisedSteps()->dangerouslyChanged();
    }

    protected function customisedSteps(): Steps
    {
        $steps = Steps::defaults();

        foreach ($this->pipelineCallbacks as $callback) {
            $steps = $callback($steps) ?? $steps;
        }

        return $steps;
    }

    /**
     * The risk engine, for choosing signals and what to do about them:
     *
     *     Keyring::risk()->signals([NewDevice::class])->respond(fn (Risk $risk) => ...);
     */
    public function risk(): RiskEngine
    {
        return $this->container->make(RiskEngine::class);
    }

    /**
     * The app's notification for each type Keyring sends, added to any set
     * before. A security notice with none isn't sent, and null takes one out
     * again. Keyring builds each through the container, passing what it has
     * to say as named constructor arguments.
     *
     * @param  array<string, class-string<Notification>|null>  $notifications
     */
    public function notifications(array $notifications): static
    {
        if ($unknown = array_diff(array_keys($notifications), self::NOTIFICATIONS)) {
            throw new InvalidArgumentException('Unknown notification types: '.implode(', ', $unknown).'. Keyring sends: '.implode(', ', self::NOTIFICATIONS).'.');
        }

        $this->notifications = array_filter([...$this->notifications, ...$notifications]);

        return $this;
    }

    public function hasNotification(string $type): bool
    {
        return isset($this->notifications[$type]);
    }

    /**
     * The app's notification of a type, or null when it hasn't one.
     *
     * @param  array<string, mixed>  $arguments
     */
    public function notification(string $type, array $arguments = []): ?Notification
    {
        return $this->hasNotification($type)
            ? $this->container->make($this->notifications[$type], $arguments)
            : null;
    }

    /**
     * For the emails a flow can't work without, like the code for an email
     * code: the app's notification, or an exception saying which is missing.
     *
     * @param  array<string, mixed>  $arguments
     */
    public function requiredNotification(string $type, array $arguments = []): Notification
    {
        return $this->notification($type, $arguments) ?? throw MissingNotification::for($type);
    }

    /**
     * Pass or fail factor checks in tests without real codes or signatures.
     */
    public function fake(): KeyringFake
    {
        throw_if(app()->isProduction(), LogicException::class, 'Keyring::fake() cannot be used in production, where it would let wrong passwords and codes sign in. Only call it from your tests.');

        $this->container->singletonIf(KeyringFake::class);

        return $this->container->make(KeyringFake::class);
    }

    /**
     * Your action that validates and creates users at registration.
     *
     * @param  class-string<CreatesNewUsers>  $action
     */
    public function createUsersUsing(string $action): static
    {
        return $this->useAction(CreatesNewUsers::class, $action);
    }

    /**
     * Your action that validates and saves a password from a reset link.
     *
     * @param  class-string<ResetsUserPasswords>  $action
     */
    public function resetUserPasswordsUsing(string $action): static
    {
        return $this->useAction(ResetsUserPasswords::class, $action);
    }

    /**
     * Your action that validates and saves a password the user changed.
     *
     * @param  class-string<UpdatesUserPasswords>  $action
     */
    public function updateUserPasswordsUsing(string $action): static
    {
        return $this->useAction(UpdatesUserPasswords::class, $action);
    }

    /**
     * Your action that validates a requested email change.
     *
     * @param  class-string<ValidatesEmailChanges>  $action
     */
    public function validateEmailChangesUsing(string $action): static
    {
        return $this->useAction(ValidatesEmailChanges::class, $action);
    }

    /**
     * @param  class-string  $contract
     * @param  class-string  $action
     */
    protected function useAction(string $contract, string $action): static
    {
        $this->container->singleton($contract, $action);

        return $this;
    }

    /**
     * Recent security activity for a settings page.
     *
     * @return Collection<int, SecurityEvent>
     */
    public function activity(Authenticatable&Model $user, int $limit = 25): Collection
    {
        return $this->container->make(SecurityLog::class)->activity($user, $limit);
    }

    /**
     * The message for a status slug Keyring flashes or returns, such as
     * "device-revoked", from keyring::status. Null for anything else.
     */
    public function statusMessage(mixed $status): ?string
    {
        return is_string($status) && Lang::has($key = 'keyring::status.'.$status) ? __($key) : null;
    }

    /**
     * Swap one of Keyring's responses.
     *
     * @param  class-string  $contract
     * @param  class-string|Closure  $implementation
     */
    public function respondWith(string $contract, string|Closure $implementation): static
    {
        $this->container->bind($contract, $implementation);

        return $this;
    }

    public function guard(): StatefulGuard
    {
        return Auth::guard(config('keyring.guard'));
    }

    /**
     * The user signed in to Keyring's guard. Step-up middleware may sit
     * behind an app's own auth middleware, so it never relies on the default.
     *
     * @throws AuthenticationException
     */
    public function user(): Authenticatable&Model
    {
        $user = $this->guard()->user();

        return $user instanceof Model ? $user : throw new AuthenticationException(guards: [config('keyring.guard')]);
    }

    public function provider(?string $guard = null): UserProvider
    {
        $guard ??= config('keyring.guard');

        return Auth::createUserProvider(config("auth.guards.{$guard}.provider"));
    }

    /**
     * The session only keeps the user's ID, so anyone the guard's provider
     * wouldn't load back would come back as whoever else has that ID.
     */
    public function belongsToGuard(Authenticatable&Model $user): bool
    {
        $found = $this->provider()->retrieveById($user->getAuthIdentifier());

        return $found instanceof Model && $found->is($user);
    }

    /**
     * Everything the user can sign in with.
     */
    public function for(Authenticatable&Model $user): UserKeyring
    {
        throw_unless($this->usesKeyring[$user::class] ??= in_array(HasKeyring::class, class_uses_recursive($user), true), MissingTrait::on($user::class));

        return $this->container->make(UserKeyring::class, ['user' => $user]);
    }

    public function username(): string
    {
        return config('keyring.username');
    }

    /**
     * The attribute holding the user's email address, which password resets,
     * email changes and email codes use. The same as the username unless
     * users sign in with something else.
     */
    public function email(): string
    {
        return config('keyring.email');
    }

    /**
     * A typed username as Keyring stores and looks it up: trimmed and
     * lowercased, unless the app says otherwise.
     */
    public function normalizeUsername(string $username): string
    {
        return $this->usernameNormalizer === null
            ? Str::lower(trim($username))
            : ($this->usernameNormalizer)($username);
    }

    /**
     * Normalise usernames your own way, e.g. keep their case, or format phone
     * numbers. Used for lookups, rate limits, email changes and reservations.
     *
     * @param  Closure(string): string  $callback
     */
    public function normalizeUsernamesUsing(Closure $callback): static
    {
        $this->usernameNormalizer = $callback;

        return $this;
    }

    /**
     * Find the user a password sign in is for your own way, e.g. by email or
     * username, or skipping banned accounts. Return null for no account;
     * Keyring checks the password and answers the same either way.
     *
     * @param  Closure(Request): ((Authenticatable&Model)|null)  $callback
     */
    public function findUsersUsing(Closure $callback): static
    {
        $this->userFinder = $callback;

        return $this;
    }

    /**
     * The user a password sign in is for, if any: for a primary factor of
     * your own that should find users the way the password does.
     */
    public function findUser(Request $request): (Authenticatable&Model)|null
    {
        $user = $this->userFinder === null
            ? $this->provider()->retrieveByCredentials([
                $this->username() => $this->normalizeUsername((string) $request->input($this->username())),
            ])
            : ($this->userFinder)($request);

        return $user instanceof Model ? $user : null;
    }

    /**
     * Whether registering signs the new user in: pass false, or a callback
     * deciding per user, to send them to the login page instead (for
     * example until an admin approves them).
     *
     * @param  bool|(Closure(Authenticatable&Model, Request): bool)  $when
     */
    public function signInAfterRegistering(bool|Closure $when): static
    {
        $this->signInAfterRegistering = $when;

        return $this;
    }

    /**
     * Start a sign in with a factor that can, from a route of your own: a
     * social login's callback, say. It runs the same pipeline as Keyring's
     * login form (rate limits, the policy, risk), so a user with a second
     * factor is still asked for it. Answers as that form would, which for a
     * failure means throwing a ValidationException.
     *
     * @throws ValidationException
     */
    public function attempt(Request $request, string $factor = 'password'): Response
    {
        $factor = $this->factor($factor);

        abort_unless($factor instanceof PrimaryFactor && $factor->startsLogin(), 404);

        $this->container->make(AttemptStore::class)->forget(Purpose::Login);

        return $this->container->make(Verifier::class)->respond(new Context($request, Purpose::Login, $factor));
    }

    /**
     * Where emailed links start, in place of APP_URL: for an app on several
     * domains, the one this user is on. Don't take it from the request's
     * Host header, which whoever sends the request controls.
     *
     * @param  Closure(): string  $callback
     */
    public function linkRootUsing(Closure $callback): static
    {
        Url::rootUsing($callback);

        return $this;
    }

    /**
     * What Keyring keeps as a request's IP address, in the security log, on
     * devices and sessions, and in notices: return a shortened address, or
     * null to keep none. Rate limits always use the real one.
     *
     * @param  Closure(Request): (string|null)  $callback
     */
    public function recordIpsUsing(Closure $callback): static
    {
        $this->ipRecorder = $callback;

        return $this;
    }

    public function recordedIp(Request $request): ?string
    {
        return $this->ipRecorder === null ? $request->ip() : ($this->ipRecorder)($request);
    }

    /**
     * Decide who may add a sign-in method, in place of Keyring's rule that
     * an app with registration on has its users verify their email first.
     * That rule is there because anyone can register someone else's address,
     * and a sign-in method they add outlives the owner's password reset: only
     * replace it with a check that the account is really its owner's.
     *
     * @param  Closure(Authenticatable&Model): bool  $callback
     */
    public function allowEnrollmentWhen(Closure $callback): static
    {
        $this->enrollmentGate = $callback;

        return $this;
    }

    /**
     * Whether the user may add a sign-in method.
     *
     * @throws EmailVerificationRequired when registration is on and nothing proves addresses
     */
    public function allowsEnrollment(Authenticatable&Model $user): bool
    {
        if ($this->enrollmentGate !== null) {
            return ($this->enrollmentGate)($user);
        }

        $verifies = $user instanceof MustVerifyEmail && Features::enabled(Features::emailVerification());

        throw_if(Features::enabled(Features::registration()) && ! $verifies, EmailVerificationRequired::forEnrollment($user::class));

        return ! $user instanceof MustVerifyEmail || $user->hasVerifiedEmail();
    }

    /**
     * Whether registering signs this user in, for a registration flow of
     * your own that should follow the same rule.
     */
    public function signsInAfterRegistering(Authenticatable&Model $user, Request $request): bool
    {
        return is_bool($this->signInAfterRegistering)
            ? $this->signInAfterRegistering
            : ($this->signInAfterRegistering)($user, $request);
    }

    /**
     * Attributes that may only change through Keyring's flows.
     *
     * @return list<string>
     */
    public function protectedAttributes(): array
    {
        return $this->protection->all();
    }

    /**
     * Change protected attributes outside a Keyring flow, for trusted admin
     * tooling. Every use is announced with a ProtectionBypassed event.
     *
     * @template T
     *
     * @param  Closure(): T  $callback
     * @return T
     */
    public function withoutProtection(Closure $callback, ?string $reason = null): mixed
    {
        return $this->protection->bypass($callback, $reason);
    }

    /**
     * @param  class-string<Authenticator>  $model
     */
    public function useAuthenticatorModel(string $model): static
    {
        $this->authenticatorModel = $model;

        return $this;
    }

    /**
     * @return class-string<Authenticator>
     */
    public function authenticatorModel(): string
    {
        return $this->authenticatorModel;
    }

    /**
     * @param  class-string<Device>  $model
     */
    public function useDeviceModel(string $model): static
    {
        $this->deviceModel = $model;

        return $this;
    }

    /**
     * @return class-string<Device>
     */
    public function deviceModel(): string
    {
        return $this->deviceModel;
    }

    /**
     * @param  class-string<PendingChange>  $model
     */
    public function usePendingChangeModel(string $model): static
    {
        $this->pendingChangeModel = $model;

        return $this;
    }

    /**
     * @return class-string<PendingChange>
     */
    public function pendingChangeModel(): string
    {
        return $this->pendingChangeModel;
    }

    /**
     * @param  class-string<SecurityEvent>  $model
     */
    public function useSecurityEventModel(string $model): static
    {
        $this->securityEventModel = $model;

        return $this;
    }

    /**
     * @return class-string<SecurityEvent>
     */
    public function securityEventModel(): string
    {
        return $this->securityEventModel;
    }
}
