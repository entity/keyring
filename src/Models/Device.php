<?php

namespace Keyring\Models;

use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Attributes\Unguarded;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Keyring\Models\Concerns\BelongsToUser;
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
    use BelongsToUser, HasUlids, MassPrunable;

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
     * @param  Builder<static>  $query
     */
    #[Scope]
    protected function ownedBy(Builder $query, Model $user): void
    {
        $query->whereMorphedTo('authenticatable', $user);
    }

    /**
     * @param  Builder<static>  $query
     */
    #[Scope]
    protected function active(Builder $query): void
    {
        $query->whereNull('revoked_at');
    }

    /**
     * Devices signed out a month ago, or not seen for a year.
     *
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        return static::query()
            ->where('revoked_at', '<', now()->subDays(30))
            ->orWhere('last_seen_at', '<', now()->subYear());
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

        return trim(($this->name ?? __('keyring::keyring.unknown_device')).($where ? ' '.__('keyring::keyring.near', ['place' => $where]) : ''));
    }
}
