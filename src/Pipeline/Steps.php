<?php

namespace Keyring\Pipeline;

use InvalidArgumentException;
use Keyring\Pipeline\Steps\CompleteAttempt;
use Keyring\Pipeline\Steps\DetermineRequirement;
use Keyring\Pipeline\Steps\EnsureNotThrottled;
use Keyring\Pipeline\Steps\VerifyFactor;

/**
 * The ordered steps of the verification pipeline. Customise them with
 * Keyring::pipeline(fn (Steps $steps) => $steps->after(A::class, B::class)).
 */
final class Steps
{
    /**
     * @param  list<class-string>  $steps
     */
    public function __construct(
        private array $steps,
    ) {}

    public static function defaults(): self
    {
        return new self([
            EnsureNotThrottled::class,
            VerifyFactor::class,
            DetermineRequirement::class,
            CompleteAttempt::class,
        ]);
    }

    /**
     * @param  class-string  $existing
     * @param  class-string  ...$steps
     */
    public function before(string $existing, string ...$steps): self
    {
        array_splice($this->steps, $this->indexOf($existing), 0, $steps);

        return $this;
    }

    /**
     * @param  class-string  $existing
     * @param  class-string  ...$steps
     */
    public function after(string $existing, string ...$steps): self
    {
        array_splice($this->steps, $this->indexOf($existing) + 1, 0, $steps);

        return $this;
    }

    /**
     * @param  class-string  $existing
     * @param  class-string  $replacement
     */
    public function replace(string $existing, string $replacement): self
    {
        $this->steps[$this->indexOf($existing)] = $replacement;

        return $this;
    }

    /**
     * @param  class-string  $existing
     */
    public function remove(string $existing): self
    {
        array_splice($this->steps, $this->indexOf($existing), 1);

        return $this;
    }

    /**
     * @return list<class-string>
     */
    public function all(): array
    {
        return $this->steps;
    }

    private function indexOf(string $step): int
    {
        $index = array_search($step, $this->steps, true);

        return $index === false
            ? throw new InvalidArgumentException("Step [{$step}] is not in the pipeline.")
            : $index;
    }
}
