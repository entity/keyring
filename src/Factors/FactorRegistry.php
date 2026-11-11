<?php

declare(strict_types=1);

namespace Keyring\Factors;

use Closure;
use Illuminate\Container\Attributes\Singleton;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Collection;
use InvalidArgumentException;
use Keyring\Contracts\Factor;
use Keyring\Exceptions\UnknownFactor;

/**
 * The factors users may sign in with, resolved from the container once.
 */
#[Singleton]
class FactorRegistry
{
    /**
     * Until the app chooses its own: the password alone, like Fortify.
     *
     * @var list<class-string<Factor>|Factor|Closure(Container): Factor>
     */
    protected array $definitions = [Password::class];

    /** @var array<string, Closure(Container): Factor> */
    protected array $extensions = [];

    /** @var array<string, Factor>|null */
    protected ?array $resolved = null;

    /**
     * @param  list<class-string<Factor>|Factor|Closure(Container): Factor>  $factors
     */
    public function set(array $factors): void
    {
        $this->definitions = $factors;
        $this->resolved = null;
    }

    /**
     * @param  Closure(Container): Factor  $resolver
     */
    public function extend(string $key, Closure $resolver): void
    {
        $this->extensions[$key] = $resolver;
        $this->resolved = null;
    }

    public function get(string $key): Factor
    {
        return $this->all()->get($key) ?? throw UnknownFactor::named($key);
    }

    public function has(string $key): bool
    {
        return $this->all()->has($key);
    }

    /**
     * @return Collection<string, Factor>
     */
    public function all(): Collection
    {
        if ($this->resolved === null) {
            $this->resolved = [];

            foreach ($this->definitions as $definition) {
                $factor = $this->resolve($definition);
                $this->resolved[$factor->key()] = $factor;
            }

            foreach ($this->extensions as $key => $resolver) {
                $factor = $this->resolve($resolver);

                if ($factor->key() !== $key) {
                    throw new InvalidArgumentException("Factor registered as [{$key}] reports the key [{$factor->key()}].");
                }

                $this->resolved[$key] = $factor;
            }
        }

        return new Collection($this->resolved);
    }

    /**
     * @param  class-string<Factor>|Factor|Closure(Container): Factor  $definition
     */
    protected function resolve(string|Factor|Closure $definition): Factor
    {
        $factor = match (true) {
            $definition instanceof Factor => $definition,
            $definition instanceof Closure => $definition(app()),
            default => app($definition),
        };

        // Whatever a code factor's subclass set its codes to, it can't be
        // registered with ones too short or too long-lived.
        if ($factor instanceof CodeFactor) {
            $factor->ensureCodesAreSafe();
        }

        return $factor;
    }
}
