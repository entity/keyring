<?php

declare(strict_types=1);

namespace Keyring\Enrollment;

use Illuminate\Container\Attributes\Scoped;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Keyring\Support\EncryptedSession;
use TypeError;

/**
 * Keeps in-progress enrollments in the session, one per factor, and
 * remembers on the server which have been used.
 */
#[Scoped]
class EnrollmentStore
{
    public function __construct(
        protected EncryptedSession $session,
        protected CacheFactory $cache,
    ) {}

    public function put(Enrollment $enrollment): void
    {
        $this->session->put($this->key($enrollment->factor), $enrollment->toArray());
    }

    public function get(string $factor): ?Enrollment
    {
        $data = $this->session->get($this->key($factor));

        // One kept before enrollments had an ID can't be told from one that
        // was already confirmed, so it reads as gone.
        try {
            $enrollment = isset($data['id']) ? Enrollment::fromArray($data) : null;
        } catch (TypeError) {
            $enrollment = null;
        }

        if ($enrollment?->expired) {
            $this->forget($factor);

            return null;
        }

        return $enrollment;
    }

    public function forget(string $factor): void
    {
        $this->session->forget($this->key($factor));
    }

    /**
     * Take the enrollment's one confirmation: true the first time, false
     * after. Forgetting it clears the session, but where the browser holds
     * the session (the "cookie" driver) an earlier copy still has the
     * enrollment, and confirming that again would bring back a set of
     * recovery codes that had since been replaced or used. So it's
     * remembered here, in the rate limiter's store, until the enrollment
     * would have expired.
     */
    public function claim(Enrollment $enrollment): bool
    {
        return $this->cache->store(config('cache.limiter'))->add(
            'keyring:enrolled:'.sha1($enrollment->id),
            true,
            max(1, $enrollment->expiresAt - now()->getTimestamp()) + 1,
        );
    }

    protected function key(string $factor): string
    {
        return 'keyring.enrollment.'.$factor;
    }
}
