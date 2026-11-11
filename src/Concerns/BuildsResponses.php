<?php

declare(strict_types=1);

namespace Keyring\Concerns;

use Closure;
use Illuminate\Contracts\Support\Responsable;
use InvalidArgumentException;
use ReflectionClass;
use ReflectionNamedType;
use ReflectionParameter;

/**
 * Keyring's responses, each behind a contract the app can answer its own way.
 */
trait BuildsResponses
{
    /**
     * Swap one of Keyring's responses for a class of your own, or a closure
     * that builds one. A class is checked now, so one Keyring couldn't build
     * stops the app at boot rather than at the first sign in.
     *
     * @param  class-string<Responsable>  $contract
     * @param  class-string<Responsable>|Closure  $implementation
     *
     * @throws InvalidArgumentException
     */
    public function respondWith(string $contract, string|Closure $implementation): static
    {
        if (is_string($implementation)) {
            $this->ensureBuildable($contract, $implementation);
        }

        app()->bind($contract, $implementation);

        return $this;
    }

    /**
     * Build the response for a contract: the app's when it swapped it, else
     * Keyring's. What it's built with goes by constructor parameter name,
     * and each contract's BUILT_WITH says which names those are.
     *
     * @template TResponse of Responsable
     *
     * @param  class-string<TResponse>  $contract
     * @return TResponse
     */
    public function response(string $contract, mixed ...$with): Responsable
    {
        return app($contract, $with);
    }

    /**
     * The container fills a constructor from what Keyring passes, by name,
     * and resolves classes itself. A required parameter it can do neither
     * for would only fail when the response is first needed.
     *
     * @param  class-string  $contract
     */
    protected function ensureBuildable(string $contract, string $implementation): void
    {
        if (! is_a($implementation, $contract, true)) {
            throw new InvalidArgumentException("Response [{$implementation}] must implement [{$contract}].");
        }

        $passed = defined($contract.'::BUILT_WITH') ? constant($contract.'::BUILT_WITH') : [];

        $unfillable = array_find(
            new ReflectionClass($implementation)->getConstructor()?->getParameters() ?? [],
            fn (ReflectionParameter $parameter) => ! in_array($parameter->getName(), $passed, true)
                && ! $parameter->isOptional()
                && (! $parameter->getType() instanceof ReflectionNamedType || $parameter->getType()->isBuiltin()),
        );

        if ($unfillable !== null) {
            throw new InvalidArgumentException(sprintf(
                'Response [%s] asks for $%s, which Keyring can\'t give it. A [%s] is built with %s.',
                $implementation,
                $unfillable->getName(),
                class_basename($contract),
                $passed === [] ? 'nothing' : implode(', ', array_map(fn (string $name) => '$'.$name, $passed)),
            ));
        }
    }
}
