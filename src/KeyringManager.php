<?php

namespace Keyring;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Inertia\Inertia;
use Keyring\Contracts\Factor;
use Keyring\Exceptions\UnknownFactor;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Pipeline\Steps;

class KeyringManager
{
    /** @var list<class-string<Factor>|Factor|Closure(Container): Factor> */
    protected array $factorDefinitions = [Password::class, Totp::class, RecoveryCodes::class];

    /** @var array<string, Factor>|null */
    protected ?array $resolvedFactors = null;

    /** @var array<string, Closure(Container): Factor> */
    protected array $extensions = [];

    /** @var Closure(Authenticatable&Model, Attempt): Requirement|Requirement */
    protected Closure|Requirement $policy;

    /** @var array<string, string|Closure(array<string, mixed>): mixed> */
    protected array $pages = [];

    /** @var list<Closure(Steps): (Steps|null)> */
    protected array $pipelineCallbacks = [];

    /** @var class-string<Authenticator> */
    protected string $authenticatorModel = Authenticator::class;

    public function __construct(
        protected Container $container,
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
        $this->factorDefinitions = $factors;
        $this->resolvedFactors = null;

        return $this;
    }

    /**
     * Register a custom factor.
     *
     * @param  Closure(Container): Factor  $resolver
     */
    public function extend(string $key, Closure $resolver): static
    {
        $this->extensions[$key] = $resolver;
        $this->resolvedFactors = null;

        return $this;
    }

    public function factor(string $key): Factor
    {
        return $this->registered()->get($key) ?? throw UnknownFactor::named($key);
    }

    public function hasFactor(string $key): bool
    {
        return $this->registered()->has($key);
    }

    /**
     * @return Collection<string, Factor>
     */
    public function registered(): Collection
    {
        if ($this->resolvedFactors === null) {
            $this->resolvedFactors = [];

            foreach ([...$this->factorDefinitions, ...array_values($this->extensions)] as $definition) {
                $factor = match (true) {
                    $definition instanceof Factor => $definition,
                    $definition instanceof Closure => $definition($this->container),
                    default => $this->container->make($definition),
                };

                $this->resolvedFactors[$factor->key()] = $factor;
            }
        }

        return new Collection($this->resolvedFactors);
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

    public function requirementFor(Authenticatable&Model $user, Attempt $attempt): Requirement
    {
        $requirement = $this->policy instanceof Closure
            ? ($this->policy)($user, $attempt)
            : $this->policy;

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
        return new UserKeyring($user);
    }

    public function username(): string
    {
        return config('keyring.username');
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
}
