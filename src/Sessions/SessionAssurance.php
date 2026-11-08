<?php

namespace Keyring\Sessions;

use Illuminate\Contracts\Session\Session;
use Keyring\Enums\Assurance;
use Keyring\Login\Requirement;
use Keyring\Login\Verification;

/**
 * What the signed-in user has proved during this session, and when. Used by
 * the assurance and freshness middleware.
 *
 * Each level lapses on its own clock, as NIST SP 800-63B asks: it only counts
 * verifications made within its overall limit (sessions.levels.aal2.absolute,
 * 24 hours by default), and inactivity past its idle limit (an hour at AAL2)
 * lapses it until the user verifies again. The session itself stays signed
 * in at whatever level is left.
 */
class SessionAssurance
{
    public const string KEY = 'keyring.verified';

    /** When the session was last active, for the idle limits. */
    public const string ACTIVE = 'keyring.active_at';

    /** The highest level inactivity left the session, until it verifies again. */
    public const string CEILING = 'keyring.ceiling';

    public function __construct(
        protected Session $session,
        protected Sessions $sessions,
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

        // Verifying again resets both clocks.
        $this->session->forget(static::CEILING);
        $this->session->put(static::ACTIVE, now()->getTimestamp());
    }

    /**
     * Note a request, lapsing any level whose idle limit passed since the
     * last one. Call it before checking the level.
     */
    public function touch(): void
    {
        $now = now()->getTimestamp();
        $active = $this->session->get(static::ACTIVE);

        if (is_int($active)) {
            $lapsed = array_find([Assurance::AAL1, Assurance::AAL2, Assurance::AAL3], function (Assurance $level) use ($now, $active) {
                $idle = $this->sessions->idle($level);

                return $idle !== null && $now - $active > $idle;
            });

            if ($lapsed !== null) {
                $this->session->put(static::CEILING, min($lapsed->value - 1, $this->session->get(static::CEILING, Assurance::AAL3->value)));
            }
        }

        $this->session->put(static::ACTIVE, $now);
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

    /**
     * The highest level the session holds right now.
     */
    public function level(): Assurance
    {
        return array_find(
            [Assurance::AAL3, Assurance::AAL2, Assurance::AAL1],
            fn (Assurance $level) => Requirement::for($level)->isMetBy($this->countingToward($level)),
        ) ?? Assurance::None;
    }

    /**
     * The verifications that still count toward a level: none once
     * inactivity lapsed it, otherwise those within its overall limit.
     *
     * @return list<Verification>
     */
    public function countingToward(Assurance $level): array
    {
        if ($level->value > $this->session->get(static::CEILING, Assurance::AAL3->value)) {
            return [];
        }

        return $this->since(now()->getTimestamp() - $this->sessions->absolute($level));
    }

    /**
     * Forget everything proved this session, including the marker that keeps
     * Laravel's own password.confirm middleware satisfied.
     */
    public function flush(): void
    {
        $this->session->forget([static::KEY, static::CEILING, 'auth.password_confirmed_at']);
    }
}
