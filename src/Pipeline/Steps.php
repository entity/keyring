<?php

declare(strict_types=1);

namespace Keyring\Pipeline;

use InvalidArgumentException;
use Keyring\Pipeline\Steps\AssessRisk;
use Keyring\Pipeline\Steps\CompleteAttempt;
use Keyring\Pipeline\Steps\DetermineRequirement;
use Keyring\Pipeline\Steps\EnsureNotRiskLocked;
use Keyring\Pipeline\Steps\EnsureNotThrottled;
use Keyring\Pipeline\Steps\ResolveDevice;
use Keyring\Pipeline\Steps\VerifyFactor;

/**
 * The ordered steps of the verification pipeline. Customise them with
 * Keyring::pipeline(fn (Steps $steps) => $steps->after(A::class, B::class)).
 */
final class Steps
{
    /** The security checks that replace() and remove() refuse to touch. */
    private const array MANDATORY = [
        EnsureNotThrottled::class,
        VerifyFactor::class,
        EnsureNotRiskLocked::class,
        DetermineRequirement::class,
        CompleteAttempt::class,
    ];

    /** @var list<class-string> */
    private array $dangerouslyChanged = [];

    /**
     * Private, so a callback can't hand back a list without the mandatory steps.
     *
     * @param  list<class-string>  $steps
     */
    private function __construct(
        private array $steps,
    ) {}

    public static function defaults(): self
    {
        return new self([
            EnsureNotThrottled::class,
            VerifyFactor::class,
            ResolveDevice::class,
            EnsureNotRiskLocked::class,
            AssessRisk::class,
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
        $this->ensureNotMandatory($existing);

        array_splice($this->steps, $this->indexOf($existing), 1, [$replacement]);

        return $this;
    }

    /**
     * @param  class-string  $existing
     */
    public function remove(string $existing): self
    {
        $this->ensureNotMandatory($existing);

        array_splice($this->steps, $this->indexOf($existing), 1);

        return $this;
    }

    /**
     * Replace a step even if it's mandatory, giving up the check it performs.
     * Logs a warning and fails the conformance suite until acknowledged.
     *
     * @param  class-string  $existing
     * @param  class-string  $replacement
     */
    public function dangerouslyReplace(string $existing, string $replacement): self
    {
        array_splice($this->steps, $this->indexOf($existing), 1, [$replacement]);
        $this->dangerouslyChanged[] = $existing;

        return $this;
    }

    /**
     * Remove a step even if it's mandatory, giving up the check it performs.
     * Logs a warning and fails the conformance suite until acknowledged.
     *
     * @param  class-string  $existing
     */
    public function dangerouslyRemove(string $existing): self
    {
        array_splice($this->steps, $this->indexOf($existing), 1);
        $this->dangerouslyChanged[] = $existing;

        return $this;
    }

    /**
     * @return list<class-string>
     */
    public function all(): array
    {
        return $this->steps;
    }

    /**
     * The steps taken out with dangerouslyReplace() or dangerouslyRemove().
     *
     * @return list<class-string>
     */
    public function dangerouslyChanged(): array
    {
        return $this->dangerouslyChanged;
    }

    private function ensureNotMandatory(string $step): void
    {
        if (in_array($step, self::MANDATORY, true)) {
            throw new InvalidArgumentException("Step [{$step}] is mandatory: without it a security check stops running. Use dangerouslyReplace() or dangerouslyRemove() if you really mean to give that check up.");
        }
    }

    private function indexOf(string $step): int
    {
        $index = array_search($step, $this->steps, true);

        return $index === false
            ? throw new InvalidArgumentException("Step [{$step}] is not in the pipeline.")
            : $index;
    }
}
