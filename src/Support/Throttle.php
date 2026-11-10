<?php

namespace Keyring\Support;

use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Keyring\Contracts\Factor;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Devices\DeviceManager;
use Keyring\KeyringManager;
use Keyring\Login\Attempt;
use Keyring\Models\Device;
use Keyring\Pipeline\AccountLimit;
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
        protected CacheFactory $cache,
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
     * A sign in that names its account also counts under the name as it was
     * typed, whoever that finds, and those are the only per-account limits
     * that say so when they refuse. The account's own refuse quietly, like a
     * wrong password. Otherwise locking an account under one name would show
     * which other names are the same account's, and which have one at all.
     *
     * Browsers the account has signed in from share a bucket and an in-a-row
     * count of their own, so someone guessing elsewhere can't lock the owner
     * out. Per IP they count for that account alone, so others on a shared
     * address can't hold it up. One count for all of them, not one each: a
     * device cookie is made at every sign in from a new browser, so whoever
     * could once sign in may hold any number, and each would buy the
     * account's whole allowance of guesses again.
     *
     * The per-IP limit comes first, so an attempt the address refuses is
     * never counted against the account.
     *
     * @return list<Limit>
     */
    public function limitsFor(Factor $factor, Request $request, ?Attempt $attempt): array
    {
        $typed = $attempt === null && $factor instanceof PrimaryFactor ? $this->typedUsername($request) : '';
        $user = $attempt?->user() ?? ($typed === '' ? null : $this->keyring->findUser($request));

        $account = match (true) {
            $user !== null => $this->accountOf($user),
            $typed !== '' => 'name:'.$typed,
            default => '',
        };

        if ($account === '') {
            return [SharedLimit::perMinute(config('keyring.limits.per_ip'))->by($factor->key().'|ip|'.$request->ip())];
        }

        $known = $this->knownBrowser($request, $user, (int) $this->mark('known-since', $account));
        $since = $this->startsSignIn($factor) ? '|cleared|'.$this->mark('cleared', $account) : '';

        return [
            SharedLimit::perMinute(config('keyring.limits.per_ip'))->by($factor->key().'|ip|'.$request->ip().($known ? '|account|'.$account : '')),
            ...($typed === '' ? [] : $this->accountLimits($factor, 'typed:'.$typed.$since, $known)),
            ...array_map(fn (AccountLimit $limit) => $limit->quietly($typed !== ''), $this->accountLimits($factor, $account.$since, $known)),
        ];
    }

    /**
     * The limits that refuse without saying so, then the rest.
     *
     * @param  list<Limit>  $limits
     * @return array{list<Limit>, list<Limit>}
     */
    public function split(array $limits): array
    {
        [$quiet, $announced] = Arr::partition($limits, fn (Limit $limit) => $limit instanceof AccountLimit && $limit->quiet);

        return [array_values($quiet), array_values($announced)];
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
     * With "lock_after" set, an account locked that many times in a day on
     * a factor that can start a sign in is held: the lock stays for as long
     * as failures are remembered, or until the account's limits are cleared
     * by a password reset or Keyring::unlock(). Returns whether this
     * failure did that.
     *
     * @param  list<Limit>  $limits
     */
    public function failed(array $limits): bool
    {
        $held = false;

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
            $hold = $limit instanceof AccountLimit && $limit->holdAfter !== null && $lockouts >= $limit->holdAfter;

            $this->limiter->hit($this->lock($limit), $hold ? $this->remembered() : min($longest, $limit->decaySeconds * 2 ** ($lockouts - 1)));
            $this->limiter->clear($key);

            $held = $held || $hold;
        }

        return $held;
    }

    /**
     * The attempt succeeded, which clears an account's count. On a shared
     * limit it only takes back its own attempt: people signing in from one
     * office address don't use it up, and an attacker can't reset it with
     * their own login. A count that has since gone (its minute ended, or it
     * became a lock) has nothing to take back, and stays at nothing rather
     * than starting the next minute below zero.
     *
     * @param  list<Limit>  $limits
     */
    public function succeeded(array $limits): void
    {
        foreach ($limits as $limit) {
            match (true) {
                ! $limit instanceof SharedLimit => $this->limiter->clear($this->key($limit)),
                $this->limiter->attempts($this->key($limit)) > 0 => $this->limiter->decrement($this->key($limit), $limit->decaySeconds),
                default => null,
            };
        }
    }

    /**
     * Start the user's limits over on the factors that can start a sign in:
     * the per-minute and in-a-row counts, the locks and how long the next
     * lock would be, for known browsers and under every name they were typed
     * with. They're counted under a mark that's replaced here, so the old
     * ones are left behind to run out.
     *
     * The per-IP limits stay, or a reset would be a way around them. A
     * second factor's counts and locks stay too: a reset only proves control
     * of the mailbox, which is what they defend against, and it could be
     * repeated to keep guessing.
     */
    public function clearAccount(Authenticatable&Model $user): void
    {
        // Never the same twice and never forgotten, so no lock can outlast
        // the mark it was made under and come back with a later one.
        $this->marks()->forever($this->markKey('cleared', $this->accountOf($user)), Str::random(16));
    }

    /**
     * Stop the browsers the account has signed in from counting as known,
     * until each signs in again. Whoever held the account before a reset, a
     * password change or a sign-out everywhere may still hold its device
     * cookies, and those get no count of their own against what's set now.
     * Kept for good, like the mark above: a device row lasts as long as it's
     * used.
     */
    public function forgetBrowsers(Authenticatable&Model $user): void
    {
        $this->marks()->forever($this->markKey('known-since', $this->accountOf($user)), (string) now()->getTimestamp());
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
     * How a user is named in rate limits. By model as well as ID, so two
     * kinds of account with the same ID don't share a count.
     */
    protected function accountOf(Authenticatable&Model $user): string
    {
        return 'user:'.$user->getMorphClass().':'.$user->getAuthIdentifier();
    }

    /**
     * A mark kept for an account: the value its limits were last cleared
     * under, or when its browsers were last forgotten. Empty when it never
     * happened. Read for a name nobody has too, so it costs what a real one
     * does.
     */
    protected function mark(string $kind, string $account): string
    {
        $mark = $this->marks()->get($this->markKey($kind, $account));

        return is_scalar($mark) ? (string) $mark : '';
    }

    /**
     * Whether the factor is one a reset clears and "lock_after" can hold:
     * those that can start a sign in. A security key is the same class as a
     * passkey, but only ever comes second.
     */
    protected function startsSignIn(Factor $factor): bool
    {
        return $factor instanceof PrimaryFactor && $factor->startsLogin();
    }

    /**
     * An account's per-minute limit and its failures in a row, or those of
     * its known browsers.
     *
     * @return list<AccountLimit>
     */
    protected function accountLimits(Factor $factor, string $account, bool $known): array
    {
        $consecutive = config('keyring.limits.consecutive');

        return [
            AccountLimit::perMinute(config('keyring.limits.per_account'))
                ->by($this->bucket($factor->key(), $account, $known))
                ->holdAfter($this->startsSignIn($factor) ? config('keyring.limits.lock_after') : null),
            ...($consecutive === null ? [] : [ConsecutiveLimit::of($consecutive, $factor->key(), $account, $known)]),
        ];
    }

    protected function typedUsername(Request $request): string
    {
        return $this->keyring->normalizeUsername(Input::text($request, $this->keyring->username()));
    }

    /**
     * Whether the request's device cookie is one of the user's, and has
     * signed in since their browsers were last forgotten. Looked up whether
     * or not there's a user, and compared without loading each device's
     * owner, so a username nobody has costs the same queries as a real one.
     */
    protected function knownBrowser(Request $request, (Authenticatable&Model)|null $user, int $since): bool
    {
        $devices = $this->devices->forBrowser($request);

        return $user !== null && $devices->contains(
            fn (Device $device) => $device->authenticatable()->is($user) && ($since === 0 || $device->last_seen_at?->getTimestamp() > $since),
        );
    }

    /**
     * The key of an account's per-minute limit, or of its known browsers'.
     */
    protected function bucket(string $factor, string $account, bool $known = false): string
    {
        return $factor.'|account|'.$account.($known ? '|known' : '');
    }

    /**
     * The rate limiter key for a limit.
     */
    protected function key(Limit $limit): string
    {
        return 'keyring:'.sha1((string) $limit->key);
    }

    /**
     * How long failures in a row, and a lock that's held, are kept.
     */
    protected function remembered(): int
    {
        return Duration::seconds(config('keyring.limits.remember_failures_for'));
    }

    protected function lock(Limit $limit): string
    {
        return $this->key($limit).':locked';
    }

    /**
     * Where the marks are kept: the rate limiter's own store, next to the
     * limits they key.
     */
    protected function marks(): CacheRepository
    {
        return $this->cache->store(config('cache.limiter'));
    }

    protected function markKey(string $kind, string $account): string
    {
        return 'keyring:'.$kind.':'.sha1($account);
    }
}
