<?php

declare(strict_types=1);

namespace Keyring\Risk;

/**
 * The findings for one assessment. Scores add up, capped at 100.
 */
final readonly class Risk
{
    public int $score;

    public Level $level;

    /**
     * @param  list<Finding>  $findings
     */
    public function __construct(
        public array $findings = [],
    ) {
        $this->score = min(100, array_sum(array_map(fn (Finding $finding) => $finding->score, $findings)));
        $this->level = Level::forScore($this->score);
    }

    public function has(string $signal): bool
    {
        return array_any($this->findings, fn (Finding $finding) => $finding->signal === $signal);
    }

    /**
     * @return list<string>
     */
    public function reasons(): array
    {
        return array_map(fn (Finding $finding) => $finding->reason, $this->findings);
    }

    public function isElevated(): bool
    {
        return $this->level !== Level::Low;
    }

    /**
     * @return list<array{signal: string, score: int, reason: string}>
     */
    public function toArray(): array
    {
        return array_map(fn (Finding $finding) => $finding->toArray(), $this->findings);
    }

    /**
     * @param  list<array{signal: string, score: int, reason: string}>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(array_map(Finding::fromArray(...), $data));
    }
}
