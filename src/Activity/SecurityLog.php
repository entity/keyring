<?php

namespace Keyring\Activity;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Keyring\Devices\UserAgent;
use Keyring\Models\SecurityEvent;

/**
 * Writes and reads the security log. Never records secrets, codes, tokens
 * or session IDs.
 */
class SecurityLog
{
    /**
     * @param  array<string, mixed>  $meta
     */
    public function record(string $type, ?Authenticatable $user = null, ?string $factor = null, ?string $device = null, array $meta = []): SecurityEvent
    {
        $event = new SecurityEvent([
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
    public function alerts(Authenticatable&Model $user): Collection
    {
        $alerts = $this->query($user)
            ->whereIn('type', SecurityEvent::ALERTS)
            ->whereNull('seen_at')
            ->latest('created_at')
            ->get();

        if ($alerts->isNotEmpty()) {
            SecurityEvent::query()->whereKey($alerts->modelKeys())->update(['seen_at' => now()]);
        }

        return $alerts;
    }

    /**
     * How many events of a type the user had recently.
     */
    public function count(Authenticatable&Model $user, string $type, int $withinSeconds): int
    {
        return $this->query($user)
            ->where('type', $type)
            ->where('created_at', '>=', now()->subSeconds($withinSeconds))
            ->count();
    }

    /**
     * @return Builder<SecurityEvent>
     */
    protected function query(Authenticatable&Model $user)
    {
        return SecurityEvent::query()->whereMorphedTo('authenticatable', $user);
    }
}
