<?php

namespace Keyring\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Attributes\Unguarded;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Keyring\Enums\Severity;
use Keyring\Models\Concerns\BelongsToUser;
use Keyring\Support\Duration;

/**
 * One entry in the security log: sign ins, failures, lockouts, changes and
 * automatic actions. Never holds secrets or session IDs.
 *
 * @property string $id
 * @property string $type
 * @property Severity $severity
 * @property string|null $factor
 * @property string|null $device_id
 * @property string|null $ip
 * @property string|null $user_agent
 * @property string|null $request_id The same for every entry one request wrote
 * @property array<string, mixed>|null $meta
 * @property CarbonInterface|null $seen_at
 * @property CarbonInterface $created_at
 */
#[Table('keyring_events')]
#[Unguarded]
class SecurityEvent extends Model
{
    use BelongsToUser, HasUlids, MassPrunable;

    public const UPDATED_AT = null;

    protected function casts(): array
    {
        return [
            'severity' => Severity::class,
            'meta' => 'array',
            'seen_at' => 'datetime',
            'created_at' => 'datetime',
        ];
    }

    /**
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        return static::query()->where('created_at', '<', Duration::ago(config('keyring.security_log.keep_for')));
    }
}
