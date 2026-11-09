<?php

namespace Keyring\Activity;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Keyring\Devices\UserAgent;
use Keyring\Facades\Keyring;
use Keyring\Features;
use Keyring\Models\SecurityEvent;

/**
 * Writes and reads the security log. Never records secrets, codes, tokens
 * or session IDs.
 */
class SecurityLog
{
    /**
     * Log an event, with Features::securityLog(). Without it, nothing is kept.
     *
     * @param  array<string, mixed>  $meta
     */
    public function record(string $type, ?Authenticatable $user = null, ?string $factor = null, ?string $device = null, array $meta = []): ?SecurityEvent
    {
        if (! Features::enabled(Features::securityLog())) {
            return null;
        }

        $model = Keyring::securityEventModel();

        return $this->safely(function () use ($model, $type, $user, $factor, $device, $meta) {
            $event = new $model([
                'type' => $type,
                'factor' => $factor,
                'device_id' => $device,
                'ip' => request()->ip(),
                'user_agent' => UserAgent::from(request()),
                'meta' => $meta === [] ? null : $meta,
                'created_at' => now(),
            ]);

            if ($user instanceof Model) {
                $event->authenticatable()->associate($user);
            }

            $event->save();

            return $event;
        }, null);
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
                ->whereIn('type', config('keyring.events.alerts'))
                ->whereNull('seen_at')
                ->latest('created_at')
                ->get();

            if ($alerts->isNotEmpty()) {
                Keyring::securityEventModel()::query()->whereKey($alerts->modelKeys())->update(['seen_at' => now()]);
            }

            return $alerts;
        }, new Collection);
    }

    /**
     * How many events of a type the user had recently.
     */
    public function count(Authenticatable&Model $user, string $type, int $withinSeconds): int
    {
        return $this->safely(fn () => $this->query($user)
            ->where('type', $type)
            ->where('created_at', '>=', now()->subSeconds($withinSeconds))
            ->count(), 0);
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
        return rescue(fn () => Keyring::securityEventModel()::query()->getConnection()->transaction($callback), $fallback);
    }

    /**
     * @return Builder<SecurityEvent>
     */
    protected function query(Authenticatable&Model $user): Builder
    {
        return Keyring::securityEventModel()::query()->ownedBy($user);
    }
}
