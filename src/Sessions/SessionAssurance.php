<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Illuminate\Container\Attributes\Scoped;
use Illuminate\Contracts\Session\Session;
use Keyring\Enums\Assurance;
use Keyring\Enums\Purpose;
use Keyring\KeyringManager;
use Keyring\Login\AttemptStore;
use Keyring\Login\Verification;

/**
 * What the signed-in user has proved during this session, and when. Used by
 * the assurance and freshness middleware.
 *
 * Each level lapses on its own clock: it only counts
 * verifications made within its overall limit (sessions.levels.aal2.absolute,
 * 24 hours by default), and inactivity past its idle limit (an hour at AAL2)
 * lapses it until the user proves every factor for it again. The session
 * itself stays signed in at whatever level is left.
 */
#[Scoped]
class SessionAssurance
{
    public const string KEY = 'keyring.verified';

    /** When the session was last active, for the idle limits. */
    public const string ACTIVE = 'keyring.active_at';

    /** When inactivity last lapsed each level, keyed by the level's value. */
    public const string LAPSED = 'keyring.lapsed_at';

    public function __construct(
        protected Session $session,
        protected Sessions $sessions,
        protected KeyringManager $keyring,
    ) {}

    /**
     * Replace what's recorded, for a brand new login.
     *
     * @param  list<Verification>  $verifications
     */
    public function reset(array $verifications): void
    {
        $this->flush();
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

            // A lapsed level takes the ones above it along. What was verified
            // before now stops counting toward them, so one factor proved
            // afterwards can't bring back a level that needs two.
            if ($lapsed !== null) {
                $this->session->put(static::LAPSED, array_replace(
                    $this->session->get(static::LAPSED, []),
                    array_fill_keys(range($lapsed->value, Assurance::AAL3->value), $now),
                ));
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
     * What still counts: an authenticator removed since, say a stolen key the
     * owner took off their account, stops counting in every session it was
     * used in.
     *
     * @return list<Verification>
     */
    public function all(): array
    {
        $verifications = array_map(Verification::fromArray(...), array_values($this->session->get(static::KEY, [])));
        $ids = array_column($verifications, 'authenticator') |> array_filter(...) |> array_values(...);

        if ($ids === []) {
            return $verifications;
        }

        $kept = $this->keyring->authenticatorModel()::query()->whereKey($ids)->pluck('id')->all();

        return array_values(array_filter($verifications, fn (Verification $verification) => $verification->authenticator === null || in_array($verification->authenticator, $kept, true)));
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
        return Assurance::highest($this->countingToward(...));
    }

    /**
     * The verifications that still count toward a level: those within its
     * overall limit, and made since inactivity last lapsed it.
     *
     * @return list<Verification>
     */
    public function countingToward(Assurance $level): array
    {
        return $this->since(max(
            now()->getTimestamp() - $this->sessions->absolute($level),
            $this->session->get(static::LAPSED, [])[$level->value] ?? 0,
        ));
    }

    /**
     * Forget everything proved this session, including a confirmation in
     * progress and the marker that keeps Laravel's own password.confirm
     * middleware satisfied.
     */
    public function flush(): void
    {
        $this->session->forget([static::KEY, static::LAPSED, AttemptStore::key(Purpose::Confirm), 'auth.password_confirmed_at']);
    }
}
