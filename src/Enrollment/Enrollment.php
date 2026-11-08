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
        public array $props,
        public array $state,
        public int $expiresAt,
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

    /**
     * What's kept in the session until the enrollment is confirmed. Props
     * were for the browser and can be large (a QR code), so they're left out.
     *
     * @return array{factor: string, state: array<string, mixed>, expires_at: int}
     */
    public function toArray(): array
    {
        return ['factor' => $this->factor, 'state' => $this->state, 'expires_at' => $this->expiresAt];
    }

    /**
     * @param  array{factor: string, state: array<string, mixed>, expires_at: int}  $data
     */
    public static function fromArray(array $data): self
    {
        return new self($data['factor'], [], $data['state'], $data['expires_at']);
    }
}
