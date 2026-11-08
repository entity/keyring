<?php

namespace Keyring\Sessions;

use Illuminate\Contracts\Session\Session;
use Keyring\Enums\Assurance;
use Keyring\Login\Verification;

/**
 * What the signed-in user has proved during this session, and when. Used by
 * the assurance and freshness middleware.
 */
class SessionAssurance
{
    public const KEY = 'keyring.verified';

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
        $this->session->put(static::KEY, []);
        $this->record($verifications);
    }

    /**
     * Add verifications, keeping the latest for each authenticator.
     *
     * @param  list<Verification>  $verifications
     */
    public function record(array $verifications): void
    {
        $stored = $this->session->get(static::KEY, []);

        foreach ($verifications as $verification) {
            $stored[$verification->authenticator ?? $verification->factor] = $verification->toArray();
        }

        $this->session->put(static::KEY, $stored);
    }

    /**
     * Record a step-up confirmation. It also satisfies Laravel's own
     * password.confirm middleware, so apps can keep using it.
     *
     * @param  list<Verification>  $verifications
     */
    public function confirm(array $verifications): void
    {
        $this->record($verifications);
        $this->session->put('auth.password_confirmed_at', now()->getTimestamp());
    }

    /**
     * @return list<Verification>
     */
    public function all(): array
    {
        return array_values(array_map(Verification::fromArray(...), $this->session->get(static::KEY, [])));
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

    /**
     * Forget everything proved this session, including the marker that keeps
     * Laravel's own password.confirm middleware satisfied.
     */
    public function flush(): void
    {
        $this->session->forget([static::KEY, 'auth.password_confirmed_at']);
    }
}
