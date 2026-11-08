<?php

namespace Keyring\Models;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Attributes\Unguarded;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Carbon;

/**
 * A change to a protected attribute (like the email address) waiting for
 * confirmation, and the record that lets it be reverted afterwards.
 * Tokens are stored as SHA-256 hashes.
 *
 * @property string $id
 * @property string $attribute
 * @property string $value
 * @property string|null $previous_value
 * @property string $confirm_token
 * @property string|null $current_token
 * @property string $revert_token
 * @property Carbon|null $confirmed_at
 * @property Carbon|null $current_confirmed_at
 * @property Carbon|null $applied_at
 * @property Carbon|null $reverted_at
 * @property Carbon|null $cancelled_at
 * @property Carbon $expires_at
 * @property Carbon|null $revertable_until
 * @property Carbon|null $created_at
 */
#[Table('keyring_pending_changes')]
#[Unguarded]
#[Hidden('confirm_token', 'current_token', 'revert_token', 'value', 'previous_value')]
class PendingChange extends Model
{
    use HasUlids, MassPrunable;

    protected function casts(): array
    {
        return [
            'value' => 'encrypted',
            'previous_value' => 'encrypted',
            'confirmed_at' => 'datetime',
            'current_confirmed_at' => 'datetime',
            'applied_at' => 'datetime',
            'reverted_at' => 'datetime',
            'cancelled_at' => 'datetime',
            'expires_at' => 'datetime',
            'revertable_until' => 'datetime',
        ];
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }

    public function user(): (Authenticatable&Model)|null
    {
        $user = $this->authenticatable;

        return $user instanceof Authenticatable ? $user : null;
    }

    /**
     * Changes that ended (expired, cancelled, reverted, or past the revert
     * window) more than a month ago. They hold both addresses, encrypted.
     *
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        $cutoff = now()->subDays(30);

        return static::query()
            ->where(fn (Builder $query) => $query->whereNull('applied_at')->where('expires_at', '<', $cutoff))
            ->orWhere('revertable_until', '<', $cutoff)
            ->orWhere('cancelled_at', '<', $cutoff)
            ->orWhere('reverted_at', '<', $cutoff);
    }

    public function isPending(): bool
    {
        return $this->applied_at === null && $this->cancelled_at === null && $this->reverted_at === null && $this->expires_at->isFuture();
    }

    public function needsCurrentConfirmation(): bool
    {
        return $this->current_token !== null && $this->current_confirmed_at === null;
    }

    public function isReady(): bool
    {
        return $this->confirmed_at !== null && ! $this->needsCurrentConfirmation();
    }

    public function canRevert(): bool
    {
        return $this->reverted_at === null && $this->cancelled_at === null
            && ($this->isPending() || $this->revertable_until?->isFuture() === true);
    }

    /**
     * @param  Builder<static>  $query
     */
    protected function scopePending(Builder $query): void
    {
        $query->whereNull('applied_at')->whereNull('cancelled_at')->whereNull('reverted_at')->where('expires_at', '>', now());
    }
}
