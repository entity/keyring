<?php

namespace Keyring\Pipeline\Steps;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Events\Lockout;
use Keyring\Facades\Keyring;
use Keyring\Factors\Factor;
use Keyring\Features;
use Keyring\Pipeline\ConsecutiveLimit;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Outcome;
use Keyring\Pipeline\SharedLimit;

/**
 * Checks the factor's rate limits, counts attempts and locks out repeated failures.
 */
class EnsureNotThrottled
{
    public function __construct(
        protected RateLimiter $limiter,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        $limits = $context->factor->limits($context->request, $context->attempt);

        foreach ($limits as $limit) {
            $key = $limit instanceof ConsecutiveLimit ? static::key($limit) : $this->lock($limit);

            if ($this->limiter->tooManyAttempts($key, $limit instanceof ConsecutiveLimit ? $limit->maxAttempts : 1)) {
                return $this->lockout($context, $this->limiter->availableIn($key));
            }
        }

        // Count the attempt before verifying it, so overlapping requests
        // can't all slip under the limit while they're being checked. They're
        // counted in order, so one refused by a limit never reaches the next.
        foreach (array_filter($limits, fn (Limit $limit) => ! $limit instanceof ConsecutiveLimit) as $limit) {
            if ($this->limiter->hit(static::key($limit), $limit->decaySeconds) > $limit->maxAttempts) {
                return $this->lockout($context, $this->limiter->availableIn(static::key($limit)));
            }
        }

        $context->throttleChecked = true;

        $context = $next($context);

        foreach ($limits as $limit) {
            if ($context->outcome === Outcome::Failed) {
                $this->failed($limit);
            } elseif (in_array($context->outcome, [Outcome::Challenge, Outcome::Complete], true)) {
                $this->succeeded($limit);
            }
        }

        return $context;
    }

    /**
     * Once a key reaches its limit, lock it. Each lock lasts twice as long as
     * the last one (OWASP), up to a day. The lockout count resets a day after
     * the first lockout.
     *
     * A shared limit's lock stops growing at fifteen minutes, or everyone on
     * that address would pay for one person's failures for a day.
     */
    protected function failed(Limit $limit): void
    {
        $key = static::key($limit);

        // Counted here, not up front, so it's failures in a row: no window,
        // no lock of its own, just refused at the cap until a success.
        if ($limit instanceof ConsecutiveLimit) {
            $this->limiter->hit($key, $limit->decaySeconds);

            return;
        }

        if ($this->limiter->attempts($key) < $limit->maxAttempts) {
            return;
        }

        $lockouts = $this->limiter->hit($key.':lockouts', 86400);
        $longest = $limit instanceof SharedLimit ? SharedLimit::LONGEST_LOCK : 86400;

        $this->limiter->hit($this->lock($limit), min($longest, $limit->decaySeconds * 2 ** ($lockouts - 1)));
        $this->limiter->clear($key);
    }

    /**
     * A success clears an account's count. On a shared limit it only takes
     * back its own attempt: people signing in from one office address don't
     * use it up, and an attacker can't reset it with their own login.
     */
    protected function succeeded(Limit $limit): void
    {
        $limit instanceof SharedLimit
            ? $this->limiter->decrement(static::key($limit), $limit->decaySeconds)
            : $this->limiter->clear(static::key($limit));
    }

    protected function lockout(Context $context, int $retryAfter): Context
    {
        Lockout::dispatch($context->request, $context->factor->key(), $retryAfter);

        return $context->lockout($retryAfter);
    }

    /**
     * The rate limiter key for a limit.
     */
    public static function key(Limit $limit): string
    {
        return 'keyring:'.sha1((string) $limit->key);
    }

    protected function lock(Limit $limit): string
    {
        return static::key($limit).':locked';
    }

    /**
     * Clear the user's per-account limits on the factors that can start a
     * sign in: the in-a-row count, and the counts, locks and escalation.
     * Limits start under the typed username (before the user is known) and
     * continue under their ID, with a bucket for each known device. The
     * per-IP limits stay, or a reset would be a way around them. A second
     * factor's counts and locks stay too: a reset only proves control of the
     * mailbox, which is what they defend against, and it could be repeated to
     * keep guessing.
     *
     * The user's username is cleared by default. Apps whose findUsersUsing()
     * also accepts something else pass it in $usernames: nothing on the user
     * says what else was typed.
     */
    public static function clearAccount(Authenticatable&Model $user, ?string ...$usernames): void
    {
        $limiter = app(RateLimiter::class);

        $accounts = [
            (string) $user->getAuthIdentifier(),
            ...array_map(fn (?string $username) => Factor::accountKey((string) $username), [$user->getAttribute(Keyring::username()), ...$usernames]),
        ];

        $devices = Features::enabled(Features::devices())
            ? Keyring::deviceModel()::query()->ownedBy($user)->active()->pluck('id')->all()
            : [];

        foreach (Keyring::registered() as $name => $factor) {
            if (! $factor instanceof PrimaryFactor) {
                continue;
            }

            foreach ($accounts as $account) {
                foreach ([null, ...$devices] as $device) {
                    $key = static::key(new Limit(Factor::accountBucket($name, $account, $device)));

                    $limiter->clear($key);
                    $limiter->clear($key.':locked');
                    $limiter->clear($key.':lockouts');
                    $limiter->clear(static::key(new Limit(ConsecutiveLimit::keyFor($name, $account, $device))));
                }
            }
        }
    }
}
