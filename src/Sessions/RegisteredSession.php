<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use Keyring\Enums\Assurance;

/**
 * A signed-in session. Its ID is Keyring's own, kept inside the session, so
 * Laravel's session ID is never stored or logged.
 *
 * A session that moves to a new record leaves the old one behind, naming
 * the new one (replacedBy). It's no longer a session, but its ID can be
 * told from one never issued, and followed to the session it became.
 *
 * A remembered session is one "remember me" may bring back once Laravel's
 * own session has gone, so it's allowed to sit unused for longer.
 *
 * Whose it is takes the model as well as the ID (userType is the user's
 * morph class), as everything else Keyring keeps for a user does: two user
 * models can have the same IDs.
 */
final readonly class RegisteredSession
{
    public function __construct(
        public string $id,
        public string $userId,
        public string $userType,
        public string $guard,
        public ?string $deviceId,
        public Assurance $assurance,
        public ?string $ip,
        public ?string $userAgent,
        public int $authenticatedAt,
        public int $lastActivityAt,
        public int $expiresAt,
        public ?int $revokedAt = null,
        public ?string $replacedBy = null,
        public ?int $replacedAt = null,
        public bool $remembered = false,
    ) {}

    /**
     * Whether this is a session of that user: the same model and the same ID.
     */
    public function belongsTo(Authenticatable $user): bool
    {
        return $this->userId === (string) $user->getAuthIdentifier() && $this->userType === self::typeOf($user);
    }

    /**
     * What a user's records carry as userType.
     */
    public static function typeOf(Authenticatable $user): string
    {
        return $user instanceof Model ? $user->getMorphClass() : $user::class;
    }

    public function isActive(int $now): bool
    {
        return $this->revokedAt === null && $this->replacedBy === null && $this->expiresAt > $now;
    }

    /**
     * @param  array<string, mixed>  $changes
     */
    #[\NoDiscard]
    public function with(array $changes): self
    {
        return clone ($this, $changes);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'user_id' => $this->userId,
            'user_type' => $this->userType,
            'guard' => $this->guard,
            'device_id' => $this->deviceId,
            'assurance' => $this->assurance->value,
            'ip' => $this->ip,
            'user_agent' => $this->userAgent,
            'authenticated_at' => $this->authenticatedAt,
            'last_activity_at' => $this->lastActivityAt,
            'expires_at' => $this->expiresAt,
            'revoked_at' => $this->revokedAt,
            'replaced_by' => $this->replacedBy,
            'replaced_at' => $this->replacedAt,
            'remembered' => $this->remembered,
        ];
    }

    /**
     * Storage columns for some of the fields, e.g. ['lastActivityAt' => 1] to ['last_activity_at' => 1].
     *
     * @param  array<string, mixed>  $changes
     * @return array<string, mixed>
     */
    public static function columns(array $changes): array
    {
        return collect($changes)
            ->mapWithKeys(fn (mixed $value, string $field) => [Str::snake($field) => $value instanceof Assurance ? $value->value : $value])
            ->all();
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'],
            userId: (string) $data['user_id'],
            userType: $data['user_type'],
            guard: $data['guard'],
            deviceId: $data['device_id'],
            assurance: Assurance::from((int) $data['assurance']),
            ip: $data['ip'],
            userAgent: $data['user_agent'],
            authenticatedAt: (int) $data['authenticated_at'],
            lastActivityAt: (int) $data['last_activity_at'],
            expiresAt: (int) $data['expires_at'],
            revokedAt: $data['revoked_at'] === null ? null : (int) $data['revoked_at'],
            replacedBy: $data['replaced_by'] ?? null,
            replacedAt: isset($data['replaced_at']) ? (int) $data['replaced_at'] : null,
            remembered: (bool) ($data['remembered'] ?? false),
        );
    }
}
