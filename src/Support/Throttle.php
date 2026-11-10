<?php

namespace Keyring\Support;

use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Keyring\Contracts\Factor;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Devices\DeviceManager;
use Keyring\Features;
use Keyring\KeyringManager;
use Keyring\Login\Attempt;
use Keyring\Models\Device;
use Keyring\Pipeline\ConsecutiveLimit;
use Keyring\Pipeline\SharedLimit;

/**
 * Every rate limit on verifying a factor: the limits a factor runs under,
 * counting attempts against them, locking out repeated failures, and
 * clearing them again. What counts an attempt and what clears it sit side
 * by side, so the two can't drift apart.
 */
class Throttle
{
    public function __construct(
        protected RateLimiter $limiter,
        protected KeyringManager $keyring,
        protected DeviceManager $devices,
    ) {}

    /**
     * The limits a factor runs under unless it declares its own: per IP
     * address, per account, and failures in a row.
     *
     * The per-IP limit is a SharedLimit, so a success never clears it.
     * Requests that don't name an account (like a usernameless passkey) only
     * get the per-IP limit, so they can't fill one bucket every user shares.
     *
     * An account's limits are its user's, found first, so however the
     * username was typed they count in one place, and a success only clears
     * the counts of whoever signed in. A username that finds nobody counts
     * under what was typed.
     *
     * A browser the account has signed in from before gets a bucket and an
     * in-a-row count of its own, so someone guessing elsewhere can't lock the
     * owner out. Per IP it counts for that account alone, so others on a
     * shared address can't hold it up. That's per account rather than per
     * device so that several stolen cookies share one count.
     *
     * The per-IP limit comes first, so an attempt the address refuses is
     * never counted against the account.
     *
     * @return list<Limit>
     */
    public function limitsFor(Factor $factor, Request $request, ?Attempt $attempt): array
    {
        $user = $this->user($factor, $request, $attempt);
        $account = $user === null ? $this->unknownAccount($request) : $this->accountOf($user);
        $device = $account === '' ? null : $this->knownDevice($request, $user);
        $consecutive = config('keyring.limits.consecutive');

        $ip = $factor->key().'|ip|'.$request->ip().($device === null ? '' : '|account|'.$account);
        $limits = [SharedLimit::perMinute(config('keyring.limits.per_ip'))->by($ip)];

        if ($account !== '') {
            $limits[] = Limit::perMinute(config('keyring.limits.per_account'))->by($this->bucket($factor->key(), $account, $device));
        }

        if ($account !== '' && $consecutive !== null) {
            $limits[] = ConsecutiveLimit::of($consecutive, $factor->key(), $account, $device);
        }

        return $limits;
    }

    /**
     * Count an attempt against the limits before it's verified, so
     * overlapping requests can't all slip under one while they're being
     * checked. Returns the seconds to wait when a limit refuses it. They're
     * counted in order, so one refused by a limit never reaches the next.
     *
     * @param  list<Limit>  $limits
     */
    public function hit(array $limits): ?int
    {
        foreach ($limits as $limit) {
            $key = $limit instanceof ConsecutiveLimit ? $this->key($limit) : $this->lock($limit);

            if ($this->limiter->tooManyAttempts($key, $limit instanceof ConsecutiveLimit ? $limit->maxAttempts : 1)) {
                return $this->limiter->availableIn($key);
            }
        }

        foreach ($limits as $limit) {
            if (! $limit instanceof ConsecutiveLimit && $this->limiter->hit($this->key($limit), $limit->decaySeconds) > $limit->maxAttempts) {
                return $this->limiter->availableIn($this->key($limit));
            }
        }

        return null;
    }

    /**
     * The attempt failed. Once a key reaches its limit, lock it. Each lock
     * lasts twice as long as the last one, up to "longest_lock", and the
     * lockout count resets a day after the first lockout.
     *
     * A shared limit's lock stops growing at "longest_ip_lock", or everyone
     * on that address would pay for one person's failures for a day.
     *
     * @param  list<Limit>  $limits
     */
    public function failed(array $limits): void
    {
        foreach ($limits as $limit) {
            $key = $this->key($limit);

            // Counted here, not up front, so it's failures in a row: no window,
            // no lock of its own, just refused at the cap until a success.
            if ($limit instanceof ConsecutiveLimit) {
                $this->limiter->hit($key, $limit->decaySeconds);

                continue;
            }

            if ($this->limiter->attempts($key) < $limit->maxAttempts) {
                continue;
            }

            $lockouts = $this->limiter->hit($key.':lockouts', 86400);
            $longest = Duration::seconds(config($limit instanceof SharedLimit ? 'keyring.limits.longest_ip_lock' : 'keyring.limits.longest_lock'));

            $this->limiter->hit($this->lock($limit), min($longest, $limit->decaySeconds * 2 ** ($lockouts - 1)));
            $this->limiter->clear($key);
        }
    }

    /**
     * The attempt succeeded, which clears an account's count. On a shared
     * limit it only takes back its own attempt: people signing in from one
     * office address don't use it up, and an attacker can't reset it with
     * their own login.
     *
     * @param  list<Limit>  $limits
     */
    public function succeeded(array $limits): void
    {
        foreach ($limits as $limit) {
            $limit instanceof SharedLimit
                ? $this->limiter->decrement($this->key($limit), $limit->decaySeconds)
                : $this->limiter->clear($this->key($limit));
        }
    }

    /**
     * Clear the user's per-account limits on the factors that can start a
     * sign in: the in-a-row count, and the counts, locks and escalation, with
     * those of each known device. The per-IP limits stay, or a reset would
     * be a way around them. A second factor's counts and locks stay too: a
     * reset only proves control of the mailbox, which is what they defend
     * against, and it could be repeated to keep guessing.
     */
    public function clearAccount(Authenticatable&Model $user): void
    {
        $devices = Features::enabled(Features::devices())
            ? $this->keyring->deviceModel()::query()->ownedBy($user)->active()->pluck('id')->all()
            : [];

        $factors = $this->keyring->registered()->filter(fn (Factor $factor) => $factor instanceof PrimaryFactor)->keys();

        foreach ($factors->crossJoin([null, ...$devices]) as [$factor, $device]) {
            $key = $this->key(new Limit($this->bucket($factor, $this->accountOf($user), $device)));

            $this->limiter->clear($key);
            $this->limiter->clear($key.':locked');
            $this->limiter->clear($key.':lockouts');
            $this->limiter->clear($this->key(new Limit(ConsecutiveLimit::keyFor($factor, $this->accountOf($user), $device))));
        }
    }

    /**
     * Count a code about to be sent, and refuse it when the account has been
     * sent its limit for the factor (three every ten minutes, unless the
     * limits.codes options say otherwise). Counted per account, not per sign
     * in, so starting again doesn't buy more, and sign ins, step-ups and
     * enrollments share the count.
     *
     * @throws ValidationException
     */
    public function sending(string $factor, int|string $userId): void
    {
        $key = 'keyring-send:'.$factor.'|'.$userId;

        if ($this->limiter->tooManyAttempts($key, config('keyring.limits.codes'))) {
            throw static::exception('code', $this->limiter->availableIn($key));
        }

        $this->limiter->hit($key, Duration::seconds(config('keyring.limits.codes_per')));
    }

    /**
     * Laravel's "too many attempts" message on the field, as a 429.
     */
    public static function exception(string $field, int $seconds): ValidationException
    {
        return ValidationException::withMessages([
            $field => __('auth.throttle', ['seconds' => $seconds, 'minutes' => (int) ceil($seconds / 60)]),
        ])->status(429);
    }

    /**
     * Whose attempt this is: the user once there's an attempt, and before
     * that whoever the typed username finds, for a factor that can start a
     * sign in. Null when it names nobody Keyring knows.
     */
    protected function user(Factor $factor, Request $request, ?Attempt $attempt): (Authenticatable&Model)|null
    {
        return match (true) {
            $attempt !== null => $attempt->user(),
            $factor instanceof PrimaryFactor && $this->typedUsername($request) !== '' => $this->keyring->findUser($request),
            default => null,
        };
    }

    /**
     * How a user is named in rate limits. By model as well as ID, so two
     * kinds of account with the same ID don't share a count.
     */
    protected function accountOf(Authenticatable&Model $user): string
    {
        return 'user:'.$user->getMorphClass().':'.$user->getAuthIdentifier();
    }

    /**
     * How a username that finds nobody is named, so guesses at it are still
     * limited, and answered like guesses at a real account. Empty when the
     * request names no account at all.
     */
    protected function unknownAccount(Request $request): string
    {
        $username = $this->typedUsername($request);

        return $username === '' ? '' : 'name:'.$username;
    }

    protected function typedUsername(Request $request): string
    {
        return $this->keyring->normalizeUsername(Input::text($request, $this->keyring->username()));
    }

    /**
     * The device's ID when the request's device cookie is one of the user's.
     * Looked up whether or not there's a user, so a username nobody has
     * takes as long to turn down as a real one.
     */
    protected function knownDevice(Request $request, (Authenticatable&Model)|null $user): ?string
    {
        $devices = $this->devices->forBrowser($request);

        return $user === null ? null : $devices->first(fn (Device $device) => $device->user()?->is($user) === true)?->id;
    }

    /**
     * The key of an account's per-minute limit, or of a known device's.
     */
    protected function bucket(string $factor, string $account, ?string $device = null): string
    {
        return $factor.'|account|'.$account.($device === null ? '' : '|device|'.$device);
    }

    /**
     * The rate limiter key for a limit.
     */
    protected function key(Limit $limit): string
    {
        return 'keyring:'.sha1((string) $limit->key);
    }

    protected function lock(Limit $limit): string
    {
        return $this->key($limit).':locked';
    }
}
