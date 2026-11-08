<?php

namespace Keyring\Login;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Keyring\Enums\Purpose;
use Keyring\Exceptions\AttemptExpired;
use Keyring\Facades\Keyring;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
use Keyring\Risk\Risk;
use Keyring\Support\Duration;
use Keyring\UserKeyring;

/**
 * A half-finished verification: a login waiting for a second factor, a
 * step-up confirmation, or an account recovery.
 *
 * Stored encrypted in the session as plain JSON (never serialize()).
 */
final class Attempt
{
    /** Whether the verifications so far meet the requirement. */
    public bool $complete {
        get => $this->requirement?->isMetBy($this->verifications) ?? false;
    }

    public bool $expired {
        get => $this->expiresAt < now()->getTimestamp();
    }

    private (Authenticatable&Model)|null $resolvedUser = null;

    private ?UserKeyring $resolvedKeyring = null;

    /** Whether the user asked not to be asked again on this device. */
    public bool $trustDevice = false;

    /** The known device this attempt comes from, null for a new device. */
    public private(set) ?string $deviceId = null;

    public private(set) bool $deviceResolved = false;

    /** What the risk signals found, once assessed. */
    public ?Risk $risk = null;

    /** Whether risk asked for an extra factor. */
    public bool $stepUp = false;

    /**
     * @param  list<Verification>  $verifications
     * @param  array<string, array<string, mixed>>  $state
     * @param  array<string, string>  $presented
     */
    public function __construct(
        public readonly string $id,
        public readonly Purpose $purpose,
        public readonly string $guard,
        public readonly int|string $userId,
        public readonly int $expiresAt,
        public readonly bool $remember = false,
        public private(set) array $verifications = [],
        public ?Requirement $requirement = null,
        public private(set) array $state = [],
        public private(set) array $presented = [],
    ) {}

    /**
     * @param  list<Verification>  $verifications  what the user has already proved, for step-up
     */
    public static function start(
        Purpose $purpose,
        Authenticatable&Model $user,
        bool $remember = false,
        ?Requirement $requirement = null,
        array $verifications = [],
    ): self {
        $attempt = new self(
            id: Str::random(40),
            purpose: $purpose,
            guard: config('keyring.guard'),
            userId: $user->getAuthIdentifier(),
            expiresAt: now()->addSeconds(Duration::seconds(config('keyring.pending_login_ttl')))->getTimestamp(),
            remember: $remember,
            verifications: $verifications,
            requirement: $requirement,
        );

        $attempt->resolvedUser = $user;

        return $attempt;
    }

    public function user(): Authenticatable&Model
    {
        if ($this->resolvedUser === null) {
            $user = Keyring::provider($this->guard)->retrieveById($this->userId);

            $this->resolvedUser = $user instanceof Model ? $user : throw new AttemptExpired;
        }

        return $this->resolvedUser;
    }

    public function resolveDevice(?string $deviceId): void
    {
        $this->deviceId = $deviceId;
        $this->deviceResolved = true;
    }

    /**
     * The device this attempt comes from, if it's been seen before.
     */
    public function device(): ?Device
    {
        return $this->deviceId === null ? null : Device::find($this->deviceId);
    }

    public function isNewDevice(): bool
    {
        return $this->deviceResolved && $this->deviceId === null;
    }

    public function keyring(): UserKeyring
    {
        return $this->resolvedKeyring ??= Keyring::for($this->user());
    }

    public function record(Verification $verification): void
    {
        $this->verifications[] = $verification;

        unset($this->state[$verification->factor], $this->presented[$verification->factor]);
    }

    /**
     * Authenticators that would bring this attempt closer to complete.
     *
     * @return Collection<int, Authenticator>
     */
    public function options(): Collection
    {
        return $this->requirement === null
            ? new Collection
            : $this->keyring()->usefulFor($this->requirement, $this->verifications);
    }

    /**
     * Factor specific state, like WebAuthn options or a sent code.
     */
    public function state(string $factor, ?string $key = null, mixed $default = null): mixed
    {
        $state = $this->state[$factor] ?? [];

        return $key === null ? $state : ($state[$key] ?? $default);
    }

    public function put(string $factor, string $key, mixed $value): void
    {
        $this->state[$factor][$key] = $value;
    }

    public function forget(string $factor, ?string $key = null): void
    {
        if ($key === null) {
            unset($this->state[$factor]);
        } else {
            unset($this->state[$factor][$key]);
        }
    }

    /**
     * Remember which authenticator the challenge page showed for a factor.
     */
    public function present(Authenticator $authenticator): void
    {
        $this->presented[$authenticator->factor] = $authenticator->id;
    }

    public function presented(string $factor): ?string
    {
        return $this->presented[$factor] ?? null;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'purpose' => $this->purpose->value,
            'guard' => $this->guard,
            'user_id' => $this->userId,
            'expires_at' => $this->expiresAt,
            'remember' => $this->remember,
            'verifications' => array_map(fn (Verification $verification) => $verification->toArray(), $this->verifications),
            'requirement' => $this->requirement?->toArray(),
            'state' => $this->state,
            'presented' => $this->presented,
            'device' => ['id' => $this->deviceId, 'resolved' => $this->deviceResolved, 'trust' => $this->trustDevice],
            'risk' => $this->risk?->toArray(),
            'step_up' => $this->stepUp,
        ];
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        $attempt = new self(
            id: $data['id'],
            purpose: Purpose::from($data['purpose']),
            guard: $data['guard'],
            userId: $data['user_id'],
            expiresAt: $data['expires_at'],
            remember: $data['remember'],
            verifications: array_map(Verification::fromArray(...), $data['verifications']),
            requirement: $data['requirement'] === null ? null : Requirement::fromArray($data['requirement']),
            state: $data['state'],
            presented: $data['presented'],
        );

        $attempt->deviceId = $data['device']['id'] ?? null;
        $attempt->deviceResolved = $data['device']['resolved'] ?? false;
        $attempt->trustDevice = $data['device']['trust'] ?? false;
        $attempt->risk = isset($data['risk']) ? Risk::fromArray($data['risk']) : null;
        $attempt->stepUp = $data['step_up'] ?? false;

        return $attempt;
    }
}
