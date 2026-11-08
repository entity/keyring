<?php

namespace Keyring\Sessions;

use Keyring\Enums\Assurance;

/**
 * A signed-in session. Its ID is Keyring's own, kept inside the session, so
 * Laravel's session ID is never stored or logged.
 */
final readonly class RegisteredSession
{
    public function __construct(
        public string $id,
        public string $userId,
        public string $guard,
        public ?string $deviceId,
        public Assurance $assurance,
        public ?string $ip,
        public ?string $userAgent,
        public int $authenticatedAt,
        public int $lastActivityAt,
        public int $expiresAt,
        public ?int $revokedAt = null,
    ) {}

    public function isActive(int $now): bool
    {
        return $this->revokedAt === null && $this->expiresAt > $now;
    }

    #[\NoDiscard]
    public function with(array $changes): self
    {
        return clone ($this, $changes);
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'user_id' => $this->userId,
            'guard' => $this->guard,
            'device_id' => $this->deviceId,
            'assurance' => $this->assurance->value,
            'ip' => $this->ip,
            'user_agent' => $this->userAgent,
            'authenticated_at' => $this->authenticatedAt,
            'last_activity_at' => $this->lastActivityAt,
            'expires_at' => $this->expiresAt,
            'revoked_at' => $this->revokedAt,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'],
            userId: (string) $data['user_id'],
            guard: $data['guard'],
            deviceId: $data['device_id'],
            assurance: Assurance::from((int) $data['assurance']),
            ip: $data['ip'],
            userAgent: $data['user_agent'],
            authenticatedAt: (int) $data['authenticated_at'],
            lastActivityAt: (int) $data['last_activity_at'],
            expiresAt: (int) $data['expires_at'],
            revokedAt: $data['revoked_at'] === null ? null : (int) $data['revoked_at'],
        );
    }
}
