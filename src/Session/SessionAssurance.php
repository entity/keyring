<?php

namespace Keyring\Session;

use Illuminate\Contracts\Session\Session;
use Keyring\Enums\Assurance;
use Keyring\Login\Verification;

/**
 * What the signed-in user has proved during this session, and when. Used by
 * the assurance and freshness middleware.
 */
class SessionAssurance
{
    protected const KEY = 'keyring.verified';

    public function __construct(
        protected Session $session,
    ) {}

    /**
     * Replace what's recorded, for a brand new login.
     *
     * @param  list<Verification>  $verifications
     */
    public function reset(array $verifications): void
    {
        $this->session->put(self::KEY, []);
        $this->record($verifications);
    }

    /**
     * Add verifications, keeping the latest for each authenticator.
     *
     * @param  list<Verification>  $verifications
     */
    public function record(array $verifications): void
    {
        $stored = $this->session->get(self::KEY, []);

        foreach ($verifications as $verification) {
            $stored[$verification->authenticator ?? $verification->factor] = $verification->toArray();
        }

        $this->session->put(self::KEY, $stored);
    }

    /**
     * @return list<Verification>
     */
    public function all(): array
    {
        return array_values(array_map(Verification::fromArray(...), $this->session->get(self::KEY, [])));
    }

    /**
     * Verifications made since the given timestamp.
     *
     * @return list<Verification>
     */
    public function since(int $timestamp): array
    {
        return array_values(array_filter($this->all(), fn (Verification $verification) => $verification->at >= $timestamp));
    }

    public function level(): Assurance
    {
        return Assurance::of($this->all());
    }

    public function lastVerifiedAt(): ?int
    {
        $times = array_map(fn (Verification $verification) => $verification->at, $this->all());

        return $times === [] ? null : max($times);
    }

    public function flush(): void
    {
        $this->session->forget(self::KEY);
    }
}
