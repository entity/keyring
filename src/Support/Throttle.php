<?php

declare(strict_types=1);

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
use Keyring\Features;
use Keyring\KeyringManager;
use Keyring\Login\Attempt;
use Keyring\Models\Device;
use Keyring\Pipeline\AccountLimit;
use Keyring\Pipeline\ConsecutiveLimit;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\NameLimit;
use Keyring\Pipeline\SharedLimit;

/**
 * Every rate limit on verifying a factor: the limits a factor runs under,
 * counting attempts against them, locking out repeated failures, and
 * clearing them again. What counts an attempt and what clears it sit side
 * by side, so the two can't drift apart.
 *
 * The per-minute limits and their locks are short-lived and live in the
 * cache. Failures in a row on an account's authenticator are kept in the
 * database (FailureCounts), where clearing the cache can't reach them.
 */
class Throttle
{
    public function __construct(
        protected RateLimiter $limiter,
        protected KeyringManager $keyring,
        protected DeviceManager $devices,
        protected CacheFactory $cache,
        protected FailureCounts $counts,
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
     * Browsers the account has signed in from share a bucket of their own,
     * and part of the failures in a row is kept for them, so someone
     * guessing elsewhere can't lock the owner out. Per IP they count for
     * that account alone, so others on a shared address can't hold it up.
     * One count for all of them, not one each: a device cookie is made at
     * every sign in from a new browser, so whoever could once sign in may
     * hold any number, and each would buy the account's whole allowance of
     * guesses again.
     *
     * The per-IP limit comes first, so an attempt the address refuses is
     * never counted against the account.
     *
     * @return list<Limit>
     */
    public function limitsFor(Factor $factor, Request $request, ?Attempt $attempt): array
    {
        $typed = $attempt === null && $this->identifiesByUsername($factor) ? $this->typedUsername($request) : '';
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
        $consecutive = $this->consecutive($factor, $user, $known);

        return [
            SharedLimit::perMinute(config('keyring.limits.per_ip'))->by($factor->key().'|ip|'.$request->ip().($known ? '|account|'.$account : '')),
            ...($typed === '' ? [] : [
                $this->perMinute($factor, 'typed:'.$typed, $known)->typed(),
                ...($consecutive === null ? [] : [NameLimit::of($consecutive->share ?? PHP_INT_MAX, $factor->key(), 'typed:'.$typed, $known)]),
            ]),
            ...array_map(fn (AccountLimit $limit) => $limit->quietly($typed !== '')->unowned($user === null), [
                $this->perMinute($factor, $account.$since, $known),
                ...($consecutive === null ? [] : [$consecutive]),
            ]),
        ];
    }

    /**
     * Point the count of failures in a row at the authenticator the request
     * is for, since each has its own. A sign in that names its account by a
     * typed username hasn't found one yet, and counts against the factor:
     * the password has no row to name anyway. A challenge aimed at no
     * authenticator checks no proof, so there's nothing to count.
     *
     * @param  list<Limit>  $limits
     * @return list<Limit>
     */
    public function aim(array $limits, Context $context): array
    {
        if ($context->identifying) {
            return $limits;
        }

        foreach ($limits as $limit) {
            if ($limit instanceof ConsecutiveLimit && $context->authenticator !== null) {
                $limit->authenticator = (string) $context->authenticator->id;
            }
        }

        return $context->authenticator === null
            ? array_values(array_filter($limits, fn (Limit $limit) => ! $limit instanceof ConsecutiveLimit))
            : $limits;
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
     * checked. Returns the limit that refuses it, if one does. They're
     * counted in order, so one refused by a limit never reaches the next.
     *
     * @param  list<Limit>  $limits
     */
    public function hit(array $limits): ?Limit
    {
        foreach ($limits as $limit) {
            $refused = match (true) {
                $limit instanceof ConsecutiveLimit => $this->counts->refuses($limit),
                $limit instanceof NameLimit => $this->limiter->tooManyAttempts($this->key($limit), $limit->maxAttempts)
                    || $this->limiter->tooManyAttempts($this->lock($limit), 1),
                default => $this->limiter->tooManyAttempts($this->lock($limit), 1),
            };

            if ($refused) {
                return $limit;
            }
        }

        foreach ($limits as $limit) {
            $counted = match (true) {
                $limit instanceof ConsecutiveLimit => $this->counts->reserve($limit),
                // Counted when it fails, so it's failures in a row: no window
                // and no lock of its own, just refused at the cap.
                $limit instanceof NameLimit => true,
                default => $this->limiter->hit($this->key($limit), $limit->decaySeconds) <= $limit->maxAttempts,
            };

            if (! $counted) {
                $this->release($limits);

                return $limit;
            }
        }

        return null;
    }

    /**
     * How long until a limit that refused an attempt would let one through,
     * in seconds. Null when waiting won't do it: the authenticator is
     * refused until its failures in a row are cleared.
     */
    public function retryAfter(Limit $limit): ?int
    {
        return $limit instanceof ConsecutiveLimit
            ? null
            : max($this->limiter->availableIn($this->lock($limit)), $this->limiter->availableIn($this->key($limit)));
    }

    /**
     * The attempt failed. Once a key reaches its limit, lock it. Each lock
     * lasts twice as long as the last one, up to "longest_lock", and the
     * lockout count resets a day after the first lockout.
     *
     * A shared limit's lock stops growing at "longest_ip_lock", or everyone
     * on that address would pay for one person's failures for a day.
     *
     * The failure is also one more in a row. With "lock_after" set, an
     * account locked that many times in a day on a factor that can start a
     * sign in is held as if it had used its failures in a row up. Returns
     * whether this failure is the one that got an account's authenticator
     * refused until its count is cleared.
     *
     * @param  list<Limit>  $limits
     */
    public function failed(array $limits): bool
    {
        // The account's hold, and the typed name's, each for its own
        // lockouts. Holding the name for the account's would tell whoever
        // typed it that another name is the same account's. Holding the
        // account for the name's would count lockouts from before its
        // limits were cleared, which a name's count outlasts.
        $hold = $named = false;

        foreach ($limits as $limit) {
            $key = $this->key($limit);

            if ($limit instanceof ConsecutiveLimit) {
                continue;
            }

            if ($limit instanceof NameLimit) {
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

            $reached = $limit instanceof AccountLimit && $limit->holdAfter !== null && $lockouts >= $limit->holdAfter;

            $hold = $hold || ($reached && ! $limit->typed);
            $named = $named || ($reached && $limit->typed);
        }

        $refused = false;

        // After the locks, which decide whether to hold. The typed name is
        // held in the cache, where it's counted, for as long as that lasts.
        foreach ($limits as $limit) {
            if ($limit instanceof NameLimit && $named) {
                $this->limiter->hit($this->lock($limit), $limit->decaySeconds);
            }

            if ($limit instanceof ConsecutiveLimit) {
                $refused = $this->counts->failed($limit, $hold) || $refused;
            }
        }

        return $refused;
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
                $limit instanceof ConsecutiveLimit => $this->counts->succeeded($limit),
                ! $limit instanceof SharedLimit => $this->limiter->clear($this->key($limit)),
                $this->limiter->attempts($this->key($limit)) > 0 => $this->limiter->decrement($this->key($limit), $limit->decaySeconds),
                default => null,
            };
        }
    }

    /**
     * The attempt ended without its proof being found right or wrong: the
     * request didn't validate, say. It isn't a failure in a row, so one
     * counted going in is given back. The per-minute counts keep it.
     *
     * @param  list<Limit>  $limits
     */
    public function release(array $limits): void
    {
        foreach ($limits as $limit) {
            if ($limit instanceof ConsecutiveLimit) {
                $this->counts->release($limit);
            }
        }
    }

    /**
     * Start the user's limits over on the factors that can start a sign in:
     * the per-minute counts, the locks and how long the next lock would be,
     * for the account and its known browsers, and the failures in a row with
     * whatever they had got refused. The counts kept under the names typed
     * for it are left to run out, since the right password still gets past
     * a refused name. The limits in the cache are counted under a mark
     * that's replaced here, so the old ones are left behind to run out.
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

        $this->counts->clear($user, $this->keyring->registered()->filter($this->startsSignIn(...))->keys()->values()->all());
    }

    /**
     * Start the user's limits over on one factor, so one refused for too
     * many failures in a row works again. A factor that can start a sign in
     * shares its limits with the others that can, so they're all cleared.
     * Nothing here proves who asked: that's for whoever calls it.
     */
    public function clearFactor(Authenticatable&Model $user, Factor $factor): void
    {
        if ($this->startsSignIn($factor)) {
            $this->clearAccount($user);

            return;
        }

        // A second factor's limits aren't under the mark, and nobody types a
        // name for one, so its keys can be cleared where they are.
        foreach ([false, true] as $known) {
            $limit = $this->perMinute($factor, $this->accountOf($user), $known);

            foreach ([$this->key($limit), $this->key($limit).':lockouts', $this->lock($limit)] as $key) {
                $this->limiter->clear($key);
            }
        }

        $this->counts->clear($user, [$factor->key()]);
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
     * Give it the user: an account is its model and its ID, and two user
     * models can have the same IDs. A bare ID counts under the ID alone.
     *
     * The key is hashed so it stays short whatever the factor is called and
     * however long the account's ID is: see key().
     *
     * @throws ValidationException
     */
    public function sending(string $factor, (Authenticatable&Model)|int|string $user): void
    {
        $key = 'keyring-send:'.sha1($factor.'|'.($user instanceof Model ? $this->accountOf($user) : $user));

        if ($this->limiter->tooManyAttempts($key, config('keyring.limits.codes'))) {
            throw static::exception('code', $this->limiter->availableIn($key));
        }

        $this->limiter->hit($key, Duration::seconds(config('keyring.limits.codes_per')));
    }

    /**
     * Count a notice about to be mailed to an account or an address, and
     * return the seconds to wait when it has had its limit of that kind
     * (five an hour, unless the limits.notices options say otherwise).
     *
     * None of this mail is a guess at anything, so the factor limits never
     * see it: a sign in that succeeds isn't counted, and the form limiter
     * only counts the sender. Without a count per recipient, the app could
     * be made to mail one address as often as it can answer.
     */
    public function notifying(string $type, string $recipient): ?int
    {
        $key = 'keyring-notice:'.sha1($type.'|'.$recipient);

        if ($this->limiter->tooManyAttempts($key, config('keyring.limits.notices'))) {
            return $this->limiter->availableIn($key);
        }

        $this->limiter->hit($key, Duration::seconds(config('keyring.limits.notices_per')));

        return null;
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
     * The answer to an attempt the limits refused, on the field. A lock
     * that lifts by itself says how long it has left. Past "longest_lock"
     * it's the cap on failures in a row, or a lock that's held, and
     * counting it down helps nobody: it says what ends it instead. A
     * password reset clears a factor that can start a sign in. Any other is
     * set up again, once its user has signed in another way.
     */
    public static function lockedOut(Factor $factor, string $field, ?int $retryAfter): ValidationException
    {
        if ($retryAfter !== null && $retryAfter <= Duration::seconds(config('keyring.limits.longest_lock'))) {
            return static::exception($field, $retryAfter);
        }

        $locked = $factor instanceof PrimaryFactor && $factor->startsLogin() ? 'keyring::keyring.locked' : 'keyring::keyring.factor_locked';

        return ValidationException::withMessages([$field => __($locked)])->status(429);
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
     * An account's per-minute limit on a factor, or that of a name as it
     * was typed, for browsers the account has signed in from or for
     * everyone else. With "lock_after", enough of its lockouts in a day
     * hold a factor that can start a sign in.
     */
    protected function perMinute(Factor $factor, string $account, bool $known): AccountLimit
    {
        // Numbers set from the environment arrive as strings.
        $lockAfter = $this->startsSignIn($factor) ? config('keyring.limits.lock_after') : null;

        return AccountLimit::perMinute(config('keyring.limits.per_account'))
            ->by($this->bucket($factor->key(), $account, $known))
            ->holdAfter($lockAfter === null ? null : (int) $lockAfter);
    }

    /**
     * The failures in a row the user's authenticator allows, and how many
     * of them may come from the request's kind of browser. Null when
     * nothing counts them: no cap, and no "lock_after" to hold one either.
     *
     * Without devices no browser is known, so nothing is kept back and
     * everyone shares the whole cap.
     */
    protected function consecutive(Factor $factor, (Authenticatable&Model)|null $user, bool $known): ?ConsecutiveLimit
    {
        $cap = config('keyring.limits.consecutive');

        if ($cap === null && (! $this->startsSignIn($factor) || config('keyring.limits.lock_after') === null)) {
            return null;
        }

        $elsewhere = $known || ! Features::enabled(Features::devices()) ? null : config('keyring.limits.consecutive_elsewhere');

        return ConsecutiveLimit::of($user, $factor->key(), $known, $cap === null ? null : (int) $cap, $elsewhere === null ? null : (int) $elsewhere);
    }

    /**
     * Whether the factor finds its user by the username field. A passkey
     * doesn't: it goes by the credential, and a username sent along with
     * one is nothing to count against the account it names.
     */
    protected function identifiesByUsername(Factor $factor): bool
    {
        return $factor instanceof PrimaryFactor && array_key_exists($this->keyring->username(), $factor->identificationRules());
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
     * The rate limiter key for a limit. Every key Keyring counts under is a
     * short prefix and a hash, so that with what the rate limiter adds
     * (":timer") it fits a store with short keys: the Swoole table behind
     * Octane's "octane" store holds 63 bytes, and refuses a longer one.
     */
    protected function key(Limit $limit): string
    {
        return 'keyring:'.sha1((string) $limit->key);
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
