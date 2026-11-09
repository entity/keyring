<?php

namespace Keyring;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Inertia\Inertia;
use InvalidArgumentException;
use Keyring\Activity\SecurityLog;
use Keyring\Changes\ProtectedAttributes;
use Keyring\Contracts\CreatesNewUsers;
use Keyring\Contracts\Factor;
use Keyring\Contracts\ResetsUserPasswords;
use Keyring\Contracts\Signal;
use Keyring\Contracts\UpdatesUserPasswords;
use Keyring\Contracts\ValidatesEmailChanges;
use Keyring\Enums\Category;
use Keyring\Exceptions\MissingPage;
use Keyring\Factors\FactorRegistry;
use Keyring\Factors\RecoveryCodes;
use Keyring\Http\Middleware\PreventCaching;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
use Keyring\Models\PendingChange;
use Keyring\Models\SecurityEvent;
use Keyring\Notifications\SecurityNotice;
use Keyring\Notifications\SendSecurityNotifications;
use Keyring\Pipeline\Steps;
use Keyring\Risk\RiskEngine;
use Keyring\Testing\KeyringFake;
use LogicException;

class KeyringManager
{
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

    /** @var list<string>|null Security emails to send, null for the config value. */
    protected ?array $notifications = null;

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

        if (class_exists(Inertia::class)) {
            return Inertia::render($component, $props);
        }

        $view = str_replace('/', '.', $component);

        throw_unless(view()->exists($view), MissingPage::for($name, $view, array_keys($props)));

        return view($view, $props);
    }

    /**
     * Register Keyring's routes. Keyring does this itself unless the "routes"
     * option is false; then call it wherever you like, e.g. inside your own
     * route group with a prefix or extra middleware.
     */
    public function routes(): void
    {
        Route::middleware([...config('keyring.middleware'), PreventCaching::class])
            ->group(__DIR__.'/../routes/keyring.php');
    }

    /**
     * Change the steps a verification goes through.
     *
     * @param  Closure(Steps): (Steps|null)  $callback
     */
    public function pipeline(Closure $callback): static
    {
        $this->pipelineCallbacks[] = $callback;

        return $this;
    }

    /**
     * @return list<class-string>
     */
    public function steps(): array
    {
        $steps = Steps::defaults();

        foreach ($this->pipelineCallbacks as $callback) {
            $steps = $callback($steps) ?? $steps;
        }

        return $steps->all();
    }

    /**
     * Configure risk signals:
     *
     *     Keyring::risk([NewDevice::class, ImpossibleTravel::class])->respond(fn (Risk $risk) => ...);
     *
     * @param  list<class-string<Signal>|Signal>|null  $signals
     */
    public function risk(?array $signals = null): RiskEngine
    {
        $engine = $this->container->make(RiskEngine::class);

        return $signals === null ? $engine : $engine->signals($signals);
    }

    /**
     * Send security emails: new sign ins, password changes, failed second
     * factors and so on. Pass types to pick, or nothing for all of them.
     *
     * @param  list<string>|null  $types
     */
    public function notify(?array $types = null): static
    {
        $types ??= SendSecurityNotifications::TYPES;

        if ($unknown = array_diff($types, SendSecurityNotifications::TYPES)) {
            throw new InvalidArgumentException('Unknown security email types: '.implode(', ', $unknown).'.');
        }

        $this->notifications = $types;

        return $this;
    }

    public function notifies(string $type): bool
    {
        return in_array($type, $this->notifications ?? config('keyring.notifications', []), true);
    }

    /**
     * Pass or fail factor checks in tests without real codes or signatures.
     */
    public function fake(): KeyringFake
    {
        if (app()->environment('production')) {
            throw new LogicException('Keyring::fake() cannot be used in production, where it would let wrong passwords and codes sign in. Only call it from your tests.');
        }

        $this->container->singletonIf(KeyringFake::class);

        return $this->container->make(KeyringFake::class);
    }

    /**
     * Send security notices with your own notification, e.g. one that extends
     * Keyring's and adds Slack or the database to via().
     *
     * @param  class-string<SecurityNotice>  $notification
     */
    public function securityNoticesUsing(string $notification): static
    {
        $this->container->bind(SecurityNotice::class, $notification);

        return $this;
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
        return $this->container->make(UserKeyring::class, ['user' => $user]);
    }

    public function username(): string
    {
        return config('keyring.username');
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
     * The user a password sign in is for, if any.
     *
     * @internal
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
     * @internal
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
     * Run a Keyring flow that's allowed to change protected attributes.
     *
     * @template T
     *
     * @param  Closure(): T  $callback
     * @param  list<string>|null  $only  the attributes it may change, or all
     * @return T
     *
     * @internal
     */
    public function changing(Closure $callback, ?array $only = null): mixed
    {
        return $this->protection->changing($callback, $only);
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
     * Refuse changes to protected attributes made outside a Keyring flow.
     *
     * @internal
     */
    public function guardProtectedAttributes(Model $model): void
    {
        $this->protection->guard($model);
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
