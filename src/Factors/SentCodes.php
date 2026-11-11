<?php

namespace Keyring\Factors;

use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository as CacheRepository;

/**
 * What the server remembers about the codes a code factor sends: the code
 * waiting to be typed, the wrong guesses at it, and that it was used.
 *
 * None of it is kept in the session. Where the browser holds the session
 * (Laravel's "cookie" driver) it can send back an earlier copy, and a code
 * kept there would come back unused, with its guesses, after a newer code
 * had replaced it. Here there's one code per owner, whichever copy of the
 * session asks.
 *
 * An owner is whatever the code was sent for: a pending sign in or step-up,
 * or a user's enrollment of a factor. Kept in the rate limiter's store, next
 * to the limits on guessing, and gone the same way if that store is cleared:
 * the user asks for another code.
 */
class SentCodes
{
    public function __construct(
        protected RateLimiter $limiter,
        protected CacheFactory $cache,
    ) {}

    /**
     * The code waiting to be typed, unless it has expired.
     *
     * @return array{hash: string, expires_at: int, for: ?string}|null
     */
    public function current(string $owner): ?array
    {
        $stored = $this->store()->get($this->key('sent', $owner));
        $issued = is_string($stored) ? json_decode($stored, true) : null;

        if (! is_array($issued) || ! is_string($issued['hash'] ?? null) || ! is_int($issued['expires_at'] ?? null)) {
            return null;
        }

        return $issued['expires_at'] < now()->getTimestamp()
            ? null
            : ['hash' => $issued['hash'], 'expires_at' => $issued['expires_at'], 'for' => $issued['for'] ?? null];
    }

    /**
     * Remember a newly sent code in place of the last one, which stops
     * working. Kept as JSON, so reading it back never unserializes anything.
     *
     * @param  array{hash: string, expires_at: int, for: ?string}  $issued
     */
    public function replace(string $owner, array $issued): void
    {
        // A second longer than the code lasts, so it's the code's own expiry
        // that ends it and not the store's idea of the same moment.
        $this->store()->put($this->key('sent', $owner), json_encode($issued, JSON_THROW_ON_ERROR), $this->secondsLeft($issued) + 1);
    }

    public function forget(string $owner): void
    {
        $this->store()->forget($this->key('sent', $owner));
    }

    /**
     * Use the code up. Only one request is told it may: add() writes when
     * nothing is there yet, so of two that arrive with the same code
     * together, one finds it already used.
     *
     * @param  array{hash: string, expires_at: int, for: ?string}  $issued
     */
    public function spend(string $owner, array $issued): bool
    {
        $spent = $this->store()->add(
            $this->key('spent', $owner.'|'.$issued['hash'].'|'.$issued['expires_at']),
            true,
            $this->secondsLeft($issued) + 1,
        );

        $this->forget($owner);

        return $spent;
    }

    /**
     * The wrong guesses made so far, across every code sent for the owner.
     */
    public function guesses(string $owner): int
    {
        return (int) $this->limiter->attempts($this->key('guesses', $owner));
    }

    /**
     * Count a wrong guess, remembered for the given seconds from the first
     * one. Returns the count.
     */
    public function guessed(string $owner, int $seconds): int
    {
        return $this->limiter->hit($this->key('guesses', $owner), max(1, $seconds));
    }

    /**
     * @param  array{hash: string, expires_at: int, for: ?string}  $issued
     */
    protected function secondsLeft(array $issued): int
    {
        return max(1, $issued['expires_at'] - now()->getTimestamp());
    }

    /**
     * Short and of one length, whatever the owner: some stores cap a key's
     * length.
     */
    protected function key(string $kind, string $owner): string
    {
        return 'keyring:'.$kind.':'.sha1($owner);
    }

    /**
     * The rate limiter's own store, asked for when a code is sent or typed
     * and never while the app boots.
     */
    protected function store(): CacheRepository
    {
        return $this->cache->store(config('cache.limiter'));
    }
}
