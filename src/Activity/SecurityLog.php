<?php

declare(strict_types=1);

namespace Keyring\Activity;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Keyring\Devices\UserAgent;
use Keyring\Features;
use Keyring\KeyringManager;
use Keyring\Models\SecurityEvent;

/**
 * Writes and reads the security log. Never records secrets, codes, tokens
 * or session IDs.
 */
class SecurityLog
{
    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    /**
     * Log an event, with Features::securityLog(). Without it, nothing is kept.
     *
     * @param  array<string, mixed>  $meta
     */
    public function record(string $type, ?Authenticatable $user = null, ?string $factor = null, ?string $device = null, array $meta = []): ?SecurityEvent
    {
        return rescue(fn () => $this->recordOrFail($type, $user, $factor, $device, $meta));
    }

    /**
     * Log an event that must not happen unlogged. A failed write is thrown,
     * so whatever was about to happen doesn't. The savepoint leaves the
     * caller's transaction usable on Postgres.
     *
     * @param  array<string, mixed>  $meta
     */
    public function recordOrFail(string $type, ?Authenticatable $user = null, ?string $factor = null, ?string $device = null, array $meta = []): ?SecurityEvent
    {
        if (! Features::enabled(Features::securityLog())) {
            return null;
        }

        $event = new ($this->keyring->securityEventModel())([
            'type' => $type,
            'factor' => $factor,
            'device_id' => $device,
            'ip' => $this->keyring->recordedIp(request()),
            'user_agent' => UserAgent::from(request()),
            'meta' => $meta === [] ? null : $meta,
            'created_at' => now(),
        ]);

        if ($user instanceof Model) {
            $event->authenticatable()->associate($user);
        }

        $event->getConnection()->transaction(fn () => $event->save());

        return $event;
    }

    /**
     * Recent security activity, newest first, for a settings page.
     *
     * @return Collection<int, SecurityEvent>
     */
    public function activity(Authenticatable&Model $user, int $limit = 25): Collection
    {
        return $this->query($user)->latest('created_at')->latest('id')->limit($limit)->get();
    }

    /**
     * Unseen events worth asking "was this you?" about. Marks them seen.
     *
     * @return Collection<int, SecurityEvent>
     */
    public function pullAlerts(Authenticatable&Model $user): Collection
    {
        return $this->safely(function () use ($user) {
            $alerts = $this->query($user)
                ->whereIn('type', config('keyring.security_log.alerts'))
                ->whereNull('seen_at')
                ->latest('created_at')
                ->get();

            if ($alerts->isNotEmpty()) {
                $this->keyring->securityEventModel()::query()->whereKey($alerts->modelKeys())->update(['seen_at' => now()]);
            }

            return $alerts;
        }, new Collection);
    }

    /**
     * How many events of a type the user had recently. Given another type
     * as $since, only those after the user's last event of that one: the
     * failures since they last signed in, say.
     */
    public function count(Authenticatable&Model $user, string $type, int $withinSeconds, ?string $since = null): int
    {
        return $this->safely(function () use ($user, $type, $withinSeconds, $since) {
            // IDs are ULIDs, so a later entry has a greater one, also when
            // both were written within the same second.
            $last = $since === null ? null : $this->query($user)->where('type', $since)->max('id');

            return $this->query($user)
                ->where('type', $type)
                ->where('created_at', '>=', now()->subSeconds($withinSeconds))
                ->when($last !== null, fn (Builder $query) => $query->where('id', '>', $last))
                ->count();
        }, 0);
    }

    /**
     * The log only observes sign ins, so a failure here is reported and goes
     * no further. The savepoint stops a failed query from aborting the
     * caller's transaction on Postgres.
     *
     * @template TResult
     * @template TFallback
     *
     * @param  Closure(): TResult  $callback
     * @param  TFallback  $fallback
     * @return TResult|TFallback
     */
    protected function safely(Closure $callback, mixed $fallback): mixed
    {
        return rescue(fn () => $this->keyring->securityEventModel()::query()->getConnection()->transaction($callback), $fallback);
    }

    /**
     * @return Builder<SecurityEvent>
     */
    protected function query(Authenticatable&Model $user): Builder
    {
        return $this->keyring->securityEventModel()::query()->ownedBy($user);
    }
}
