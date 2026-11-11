<?php

namespace Keyring\Activity;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Keyring\Devices\UserAgent;
use Keyring\Enums\Severity;
use Keyring\Features;
use Keyring\KeyringManager;
use Keyring\Models\SecurityEvent;
use Keyring\Support\Duration;
use Throwable;

/**
 * Writes and reads the security log. Never records secrets, codes, tokens
 * or session IDs.
 */
class SecurityLog
{
    /**
     * Where Keyring keeps the ID it gives a request, in Laravel's hidden
     * context, when the app hasn't given it one.
     */
    public const string REQUEST_ID = 'keyring_request_id';

    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    /**
     * Log an event: in keyring_events with Features::securityLog(), and in
     * the app's log without it, so it's always recorded somewhere. An entry
     * the table won't take is reported and goes to the app's log instead.
     *
     * @param  array<string, mixed>  $meta
     */
    public function record(string $type, ?Authenticatable $user = null, ?string $factor = null, ?string $device = null, array $meta = [], ?Severity $severity = null): ?SecurityEvent
    {
        return rescue(fn () => $this->keep($this->entry($type, $user, $factor, $device, $meta, $severity), orWrite: true));
    }

    /**
     * Log an event that must not happen unlogged. A failed write is thrown,
     * so whatever was about to happen doesn't. The savepoint leaves the
     * caller's transaction usable on Postgres.
     *
     * @param  array<string, mixed>  $meta
     */
    public function recordOrFail(string $type, ?Authenticatable $user = null, ?string $factor = null, ?string $device = null, array $meta = [], ?Severity $severity = null): ?SecurityEvent
    {
        return $this->keep($this->entry($type, $user, $factor, $device, $meta, $severity));
    }

    /**
     * Log something that was refused. Whoever was refused can ask again as
     * often as they like, and the log is kept for months, so only so many
     * entries of one type are written about one account, or from one IP
     * address when the entry names nobody ("security_log.refusals" every
     * "refusals_per"). The first one left out is marked by a
     * "refusals_limited" entry, so the log says where it stopped counting.
     *
     * With $once, a refusal that repeats is written once every $for seconds:
     * a lock is logged when it starts, not each time it turns someone away.
     *
     * @param  array<string, mixed>  $meta
     */
    public function recordRefusal(string $type, ?Authenticatable $user = null, ?string $factor = null, ?string $device = null, array $meta = [], ?string $once = null, int $for = 60): ?SecurityEvent
    {
        return rescue(function () use ($type, $user, $factor, $device, $meta, $once, $for) {
            // Asked for when an entry is written, never when the app boots:
            // building the limiter takes its cache store.
            $limiter = app(RateLimiter::class);
            $about = $type.'|'.($user instanceof Model ? $user->getMorphClass().':'.$user->getKey() : 'ip:'.request()->ip());

            if ($once !== null && ! $limiter->attempt('keyring-log:'.sha1($about.'|'.$once), 1, fn () => true, max($for, 1))) {
                return null;
            }

            $limit = config('keyring.security_log.refusals');

            if ($limit === null) {
                return $this->record($type, $user, $factor, $device, $meta);
            }

            $written = $limiter->hit('keyring-log:'.sha1($about), Duration::seconds(config('keyring.security_log.refusals_per')));

            return match (true) {
                $written <= $limit => $this->record($type, $user, $factor, $device, $meta),
                $written === $limit + 1 => $this->record('refusals_limited', $user, meta: ['type' => $type]),
                default => null,
            };
        });
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
     * The entry for an event, before it's kept anywhere.
     *
     * @param  array<string, mixed>  $meta
     */
    protected function entry(string $type, ?Authenticatable $user, ?string $factor, ?string $device, array $meta, ?Severity $severity): SecurityEvent
    {
        $event = new ($this->keyring->securityEventModel())([
            'type' => $type,
            'severity' => $severity ?? Severity::of($type),
            'factor' => $factor,
            'device_id' => $device,
            'ip' => $this->keyring->recordedIp(request()),
            'user_agent' => UserAgent::from(request()),
            'request_id' => $this->requestId(),
            'meta' => $meta === [] ? null : $meta,
            'created_at' => now(),
        ]);

        if ($user instanceof Model) {
            $event->authenticatable()->associate($user);
        }

        return $event;
    }

    /**
     * Keep the entry in the table, or in the app's log when the table is
     * off. With $orWrite, one the table won't take goes there as well.
     */
    protected function keep(SecurityEvent $event, bool $orWrite = false): ?SecurityEvent
    {
        if (Features::enabled(Features::securityLog())) {
            try {
                $event->getConnection()->transaction(fn () => $event->save());

                return $event;
            } catch (Throwable $e) {
                throw_unless($orWrite, $e);

                report($e);
            }
        }

        $this->write($event);

        return null;
    }

    /**
     * The entry as a line in the app's log, at its own severity, with what
     * the table would hold as its context.
     */
    protected function write(SecurityEvent $event): void
    {
        Log::channel(config('keyring.security_log.channel'))->log($event->severity->value, 'Keyring: '.$event->type, array_filter([
            'user' => $event->authenticatable_id === null ? null : $event->authenticatable_type.':'.$event->authenticatable_id,
            'factor' => $event->factor,
            'device_id' => $event->device_id,
            'ip' => $event->ip,
            'user_agent' => $event->user_agent,
            'request_id' => $event->request_id,
            'meta' => $event->meta,
        ], fn (mixed $value) => $value !== null));
    }

    /**
     * What ties one request's entries together. An app that already names
     * its requests in Laravel's Context (under "security_log.context_key")
     * has its own ID used, so entries match its log lines. Otherwise one is
     * made and kept in the hidden context, which lasts as long as the
     * request does and stays out of the app's own log lines.
     */
    protected function requestId(): ?string
    {
        $key = config('keyring.security_log.context_key');

        if ($key === null) {
            return null;
        }

        $id = Context::get($key) ?? Context::getHidden($key);

        return Str::limit(is_scalar($id) && (string) $id !== '' ? (string) $id : Context::rememberHidden(self::REQUEST_ID, fn () => (string) Str::uuid()), 64, '');
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
