<?php

namespace Keyring\Enrollment;

use Keyring\Support\Duration;

/**
 * An authenticator being set up. Props are shown to the user; state stays on
 * the server until the enrollment is confirmed.
 */
final class Enrollment
{
    public bool $expired {
        get => $this->expiresAt < now()->getTimestamp();
    }

    /**
     * @param  array<string, mixed>  $props
     * @param  array<string, mixed>  $state
     */
    public function __construct(
        public readonly string $factor,
        public readonly array $props,
        public readonly array $state,
        public readonly int $expiresAt,
    ) {}

    /**
     * @param  array<string, mixed>  $props
     * @param  array<string, mixed>  $state
     */
    public static function make(string $factor, array $props = [], array $state = []): self
    {
        return new self($factor, $props, $state, Duration::fromNow(config('keyring.enrollments.keep_for'))->getTimestamp());
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
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self($data['factor'], [], $data['state'], $data['expires_at']);
    }
}
