<?php

declare(strict_types=1);

namespace Keyring\WebAuthn;

use Illuminate\Contracts\Cache\Factory as CacheFactory;

/**
 * Which WebAuthn challenges have been answered, remembered on the server.
 *
 * A challenge is kept in the session with what it belongs to, and taken out
 * when it's answered. Where the browser holds the session (Laravel's
 * "cookie" driver) an earlier copy still has it, and the signed answer a
 * key already gave could be sent with that copy again. A key that counts
 * its signatures gives that away. A synced passkey, whose count stays at
 * zero, doesn't. So an answered challenge is remembered here, whichever
 * copy of the session it comes back in.
 *
 * Kept in the rate limiter's store, like a used code (SentCodes), until the
 * challenge would have expired anyway.
 */
class SpentChallenges
{
    public function __construct(
        protected CacheFactory $cache,
    ) {}

    /**
     * Use a challenge up, whatever becomes of the answer. Only one request
     * is told it may: add() writes when nothing is there yet, so of two
     * that answer the same challenge together, one finds it already used.
     *
     * @param  string  $options  the options the challenge was issued in, as they were kept
     * @param  int  $expiresAt  when what holds the challenge stops taking an answer
     */
    public function spend(string $options, int $expiresAt): bool
    {
        // The rate limiter's own store, asked for when a challenge is
        // answered and never while the app boots. A second longer than the
        // challenge lasts, so it's the challenge's own expiry that ends it.
        return $this->cache->store(config('cache.limiter'))->add(
            $this->key($options),
            true,
            max(1, $expiresAt - now()->getTimestamp()) + 1,
        );
    }

    /**
     * Short and of one length, whatever the options hold: some stores cap a
     * key's length. The options carry the challenge, 32 random bytes, so
     * their hash is as good as its own.
     */
    protected function key(string $options): string
    {
        return 'keyring:challenge:'.sha1($options);
    }
}
