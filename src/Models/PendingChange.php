<?php

namespace Keyring\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Attributes\Unguarded;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use Keyring\Facades\Keyring;
use Keyring\Models\Concerns\BelongsToUser;
use Keyring\Models\Concerns\HashesTokens;
use Keyring\Support\Duration;
use Keyring\Support\KeyedHash;
use Normalizer;

/**
 * A change to a protected attribute (like the email address) waiting for
 * confirmation, and the record that lets it be reverted afterwards.
 * Tokens are stored as SHA-256 hashes. The previous value is encrypted, with
 * a keyed hash beside it so it can be found while it's reserved.
 *
 * @property string $id
 * @property string $attribute
 * @property string $value
 * @property string|null $previous_value
 * @property string|null $previous_value_hash
 * @property string $confirm_token
 * @property string|null $current_token
 * @property string $revert_token
 * @property CarbonInterface|null $confirmed_at
 * @property CarbonInterface|null $current_confirmed_at
 * @property CarbonInterface|null $applied_at
 * @property CarbonInterface|null $reverted_at
 * @property CarbonInterface|null $cancelled_at
 * @property CarbonInterface|null $signed_in_at When the session that asked for the change signed in
 * @property CarbonInterface $expires_at
 * @property CarbonInterface|null $revertable_until
 * @property CarbonInterface|null $created_at
 */
#[Table('keyring_pending_changes')]
#[Unguarded]
#[Hidden('confirm_token', 'current_token', 'revert_token', 'value', 'previous_value', 'previous_value_hash')]
class PendingChange extends Model
{
    use BelongsToUser, HashesTokens, HasUlids, MassPrunable;

    protected static function booted(): void
    {
        static::saving(function (self $change) {
            if ($change->isDirty('previous_value')) {
                $change->previous_value_hash = $change->previous_value === null ? null : static::lookupHash($change->previous_value);
            }
        });
    }

    /**
     * Whether the token is the one stored in the given token column.
     *
     * @param  'confirm_token'|'current_token'|'revert_token'  $column
     */
    public function matches(string $column, #[\SensitiveParameter] string $token): bool
    {
        return $this->{$column} !== null && hash_equals($this->{$column}, static::hashToken($token));
    }

    /**
     * How a previous value is found while it's reserved: folded, and hashed
     * with a key of its own since the value itself is encrypted.
     */
    public static function lookupHash(string $value): string
    {
        return KeyedHash::make(KeyedHash::RESERVED_ADDRESSES, static::fold($value));
    }

    /**
     * The value as the loosest database would compare it: normalised like a
     * username, then without accents, case, width or characters that don't
     * show. MySQL's default collations take "tàylor@example.com" for
     * "taylor@example.com", so a reserved address has to be found under
     * every spelling its unique index would refuse, or the lookalike could
     * be registered and leave a revert nowhere to put the address back.
     * Folding too much only keeps a similar address back while the
     * reservation lasts.
     */
    public static function fold(string $value): string
    {
        $value = Keyring::normalizeUsername($value);
        $value = Normalizer::normalize($value, Normalizer::NFKD) ?: $value;
        $value = preg_replace('/[\p{M}\p{C}\s]+/u', '', $value) ?? $value;

        return Str::lower(Str::transliterate($value, ''));
    }

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
            'signed_in_at' => 'datetime',
            'expires_at' => 'datetime',
            'revertable_until' => 'datetime',
        ];
    }

    /**
     * Changes that ended (expired, cancelled, reverted, or past the revert
     * window) more than a month ago. They hold both addresses, encrypted.
     *
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        $cutoff = Duration::ago(config('keyring.email_changes.keep_ended_for'));

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

    /**
     * A cancelled change stays revertable until it would have expired
     * (EmailChanges::cancel() sets revertable_until).
     */
    public function canRevert(): bool
    {
        return $this->reverted_at === null
            && ($this->isPending() || $this->revertable_until?->isFuture() === true);
    }

    /**
     * @param  Builder<static>  $query
     */
    #[Scope]
    protected function pending(Builder $query): void
    {
        $query->whereNull('applied_at')->whereNull('cancelled_at')->whereNull('reverted_at')->where('expires_at', '>', now());
    }

    /**
     * Applied changes that can still be reverted, which keep the address they
     * replaced for their owner (see ReservedAddresses). The SQL twin of
     * canRevert() for applied changes: keep the two in step.
     *
     * @param  Builder<static>  $query
     */
    #[Scope]
    protected function reserving(Builder $query, string $value): void
    {
        $query->whereIn('previous_value_hash', KeyedHash::candidates(KeyedHash::RESERVED_ADDRESSES, static::fold($value)))
            ->whereNotNull('applied_at')
            ->whereNull('cancelled_at')
            ->whereNull('reverted_at')
            ->where('revertable_until', '>', now());
    }
}
