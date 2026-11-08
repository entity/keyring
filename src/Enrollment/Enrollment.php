<?php

namespace Keyring\Enrollment;

/**
 * An authenticator being set up. Props are shown to the user; state stays on
 * the server until the enrollment is confirmed.
 */
final readonly class Enrollment
{
    /**
     * @param  array<string, mixed>  $props
     * @param  array<string, mixed>  $state
     */
    public function __construct(
        public string $factor,
        public array $props = [],
        public array $state = [],
        public int $expiresAt = 0,
    ) {}

    public static function make(string $factor, array $props = [], array $state = []): self
    {
        return new self($factor, $props, $state, now()->addMinutes(15)->getTimestamp());
    }

    #[\NoDiscard]
    public function with(string $key, mixed $value): self
    {
        return clone ($this, ['state' => [...$this->state, $key => $value]]);
    }

    public function state(string $key, mixed $default = null): mixed
    {
        return $this->state[$key] ?? $default;
    }

    public function expired(): bool
    {
        return $this->expiresAt < now()->getTimestamp();
    }

    public function toArray(): array
    {
        return [
            'factor' => $this->factor,
            'props' => $this->props,
            'state' => $this->state,
            'expires_at' => $this->expiresAt,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self($data['factor'], $data['props'], $data['state'], $data['expires_at']);
    }
}
