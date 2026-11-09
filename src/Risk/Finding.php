<?php

namespace Keyring\Risk;

/**
 * What one signal noticed, and how much it matters (0-100).
 */
final readonly class Finding
{
    public function __construct(
        public string $signal,
        public int $score,
        public string $reason,
    ) {}

    /**
     * @return array{signal: string, score: int, reason: string}
     */
    public function toArray(): array
    {
        return ['signal' => $this->signal, 'score' => $this->score, 'reason' => $this->reason];
    }

    /**
     * @param  array{signal: string, score: int, reason: string}  $data
     */
    public static function fromArray(array $data): self
    {
        return new self($data['signal'], $data['score'], $data['reason']);
    }
}
