<?php

namespace Keyring\Models;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Attributes\Unguarded;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Carbon;
use Keyring\Support\Url;

/**
 * A browser or app the user has signed in from, recognised by a long-lived
 * device cookie. A device is a risk signal, never a factor.
 *
 * @property string $id
 * @property string $token_hash
 * @property string|null $name
 * @property string|null $user_agent
 * @property string|null $ip
 * @property array<string, mixed>|null $location
 * @property Carbon|null $first_seen_at
 * @property Carbon|null $last_seen_at
 * @property Carbon|null $trusted_until
 * @property Carbon|null $revoked_at
 */
#[Table('keyring_devices')]
#[Unguarded]
#[Hidden('token_hash', 'authenticatable_type', 'authenticatable_id')]
class Device extends Model
{
    use HasUlids;

    protected function casts(): array
    {
        return [
            'location' => 'array',
            'first_seen_at' => 'datetime',
            'last_seen_at' => 'datetime',
            'trusted_until' => 'datetime',
            'revoked_at' => 'datetime',
        ];
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }

    public function user(): ?Authenticatable
    {
        $user = $this->authenticatable;

        return $user instanceof Authenticatable ? $user : null;
    }

    public function isTrusted(): bool
    {
        return $this->revoked_at === null && $this->trusted_until?->isFuture() === true;
    }

    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
    }

    /**
     * A signed link for "this wasn't me" emails. Signs the device out
     * everywhere without needing the user to be signed in.
     */
    public function revokeUrl(int $days = 7): string
    {
        return Url::signed('keyring.devices.report', now()->addDays($days), ['device' => $this->id]);
    }

    /**
     * "Firefox on Windows, near Manchester"
     */
    public function description(): string
    {
        $where = $this->location['city'] ?? $this->location['region'] ?? $this->location['country'] ?? null;

        return trim(($this->name ?? __('Unknown device')).($where ? ' '.__('near :place', ['place' => $where]) : ''));
    }
}
