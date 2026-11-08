<?php

namespace Keyring;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Illuminate\Validation\Rules\Password as PasswordRule;
use Inertia\Inertia;
use InvalidArgumentException;
use Keyring\Activity\SecurityLog;
use Keyring\Changes\ProtectedAttributes;
use Keyring\Contracts\CreatesNewUsers;
use Keyring\Contracts\Factor;
use Keyring\Contracts\Signal;
use Keyring\Factors\FactorRegistry;
use Keyring\Http\Middleware\PreventCaching;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
use Keyring\Models\SecurityEvent;
use Keyring\Notifications\SendSecurityNotifications;
use Keyring\Pipeline\Steps;
use Keyring\Risk\RiskEngine;
use Keyring\Testing\KeyringFake;

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

    /** @var (Closure(PasswordRule, (Authenticatable&Model)|null): PasswordRule)|null */
    protected ?Closure $passwordRules = null;

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
     * What this user must prove to complete the attempt.
     */
    public function requirementFor(Authenticatable&Model $user, Attempt $attempt): Requirement
    {
        $requirement = $this->policy($user, $attempt);

        if ($requirement->noDowngrade && ! $requirement->requiresPhishingResistance
            && $attempt->keyring()->canMeet(Requirement::aal1()->phishingResistant())) {
            $requirement = $requirement->withoutDowngrades();
        }

        if ($requirement->onlyIfEnrolled && ! $attempt->keyring()->canMeet($requirement)) {
            return Requirement::aal1();
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

        return match (true) {
            $component instanceof Closure => $component($props),
            class_exists(Inertia::class) => Inertia::render($component, $props),
            default => view(str_replace('/', '.', $component), $props),
        };
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
     * Adjust the password rule Keyring builds (its length depends on whether
     * the user has MFA), e.g. fn (Password $rule, ?User $user) => $rule->mixedCase().
     *
     * @param  Closure(PasswordRule, (Authenticatable&Model)|null): PasswordRule  $callback
     */
    public function passwordRulesUsing(Closure $callback): static
    {
        $this->passwordRules = $callback;

        return $this;
    }

    /**
     * @internal
     */
    public function adjustPasswordRule(PasswordRule $rule, (Authenticatable&Model)|null $user): PasswordRule
    {
        return $this->passwordRules === null ? $rule : ($this->passwordRules)($rule, $user);
    }

    /**
     * Pass or fail factor checks in tests without real codes or signatures.
     */
    public function fake(): KeyringFake
    {
        $this->container->singletonIf(KeyringFake::class);

        return $this->container->make(KeyringFake::class);
    }

    /**
     * Use your action to create users at registration.
     *
     * @param  class-string<CreatesNewUsers>  $action
     */
    public function createUsersUsing(string $action): static
    {
        $this->container->singleton(CreatesNewUsers::class, $action);

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
     * lowercased.
     */
    public function normalizeUsername(string $username): string
    {
        return Str::lower(trim($username));
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
     * @return T
     *
     * @internal
     */
    public function changing(Closure $callback): mixed
    {
        return $this->protection->changing($callback);
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
}
