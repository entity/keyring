<?php

declare(strict_types=1);

namespace Keyring\Sso;

use Illuminate\Container\Attributes\Scoped;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Keyring\Support\EncryptedSession;
use TypeError;

/**
 * Keeps the authorization requests a browser has started in its session,
 * keyed by state, until their callback takes them.
 *
 * A browser can have a few going at once (two tabs, a button clicked twice),
 * but no more than MAX: each new one past that takes the place of the
 * oldest, so a script can't fill the session by starting sign ins.
 */
#[Scoped]
class PendingAuthorizations
{
    public const int MAX = 5;

    protected const string KEY = 'keyring.sso';

    public function __construct(
        protected EncryptedSession $session,
        protected CacheFactory $cache,
    ) {}

    public function put(AuthorizationRequest $request): void
    {
        $pending = array_filter($this->all(), fn (AuthorizationRequest $kept) => ! $kept->expired);
        $pending[$request->state] = $request;

        $this->save(array_slice($pending, -static::MAX, preserve_keys: true));
    }

    /**
     * The request a callback's state names, left where it is: to see what a
     * callback is for before deciding who may finish it. Null when there's
     * none, or it expired. Only pull() makes it count.
     */
    public function find(string $state): ?AuthorizationRequest
    {
        $request = $this->all()[$state] ?? null;

        return $request === null || $request->expired ? null : $request;
    }

    /**
     * Take the request a callback's state names, which is then gone whatever
     * the callback goes on to do: a state works once, even when the sign in
     * fails. Null when there's none, or it expired.
     *
     * Forgetting it clears the session, but where the browser holds the
     * session (the "cookie" driver) an earlier copy still has it. So the
     * state is also claimed in the rate limiter's store, as an enrollment's
     * confirmation is, until it would have expired.
     */
    public function pull(string $state): ?AuthorizationRequest
    {
        $pending = $this->all();
        $request = $pending[$state] ?? null;

        if ($request === null) {
            return null;
        }

        unset($pending[$state]);
        $this->save($pending);

        if ($request->expired || ! $this->claim($request)) {
            return null;
        }

        return $request;
    }

    /**
     * Take the request a callback's state names once it has expired, to
     * say where the callback should go now: it's gone, and doesn't count.
     * Null when there's none, or it hasn't expired. An expired one is kept
     * until the next put(), so a callback that comes back late still finds
     * it.
     */
    public function pullExpired(string $state): ?AuthorizationRequest
    {
        $pending = $this->all();
        $request = $pending[$state] ?? null;

        if ($request === null || ! $request->expired) {
            return null;
        }

        unset($pending[$state]);
        $this->save($pending);

        return $request;
    }

    /**
     * @return array<string, AuthorizationRequest>
     */
    protected function all(): array
    {
        $pending = [];

        foreach ($this->session->get(static::KEY) ?? [] as $state => $data) {
            try {
                $pending[(string) $state] = AuthorizationRequest::fromArray($data);
            } catch (TypeError) {
                // One that can't be read back is as good as gone.
            }
        }

        return $pending;
    }

    /**
     * @param  array<string, AuthorizationRequest>  $pending
     */
    protected function save(array $pending): void
    {
        if ($pending === []) {
            $this->session->forget(static::KEY);

            return;
        }

        $this->session->put(static::KEY, array_map(fn (AuthorizationRequest $request) => $request->toArray(), $pending));
    }

    protected function claim(AuthorizationRequest $request): bool
    {
        return $this->cache->store(config('cache.limiter'))->add(
            'keyring:sso:state:'.hash('sha256', $request->state),
            true,
            max(1, $request->expiresAt - now()->getTimestamp()) + 1,
        );
    }
}
