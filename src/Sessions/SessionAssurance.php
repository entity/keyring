<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Illuminate\Container\Attributes\Scoped;
use Illuminate\Contracts\Session\Session;
use Keyring\Enums\Assurance;
use Keyring\Enums\Purpose;
use Keyring\KeyringManager;
use Keyring\Login\AttemptStore;
use Keyring\Login\Requirement;
use Keyring\Login\Verification;

/**
 * What the signed-in user has proved during this session, and when. Used by
 * the assurance and freshness middleware.
 *
 * Each level lapses on its own clock: it only counts
 * verifications made within its overall limit (sessions.levels.aal2.absolute,
 * 24 hours by default), and inactivity past its idle limit (an hour at AAL2)
 * lapses it until the user proves every factor for it again. The session
 * itself stays signed in at whatever level is left, unless
 * sessions.end_on_lapse says a session ends with the level it signed in at.
 */
#[Scoped]
class SessionAssurance
{
    public const string KEY = 'keyring.verified';

    /** When the session was last active, for the idle limits. */
    public const string ACTIVE = 'keyring.active_at';

    /** When inactivity last lapsed each level, keyed by the level's value. */
    public const string LAPSED = 'keyring.lapsed_at';

    /** The level the session signed in at, as its value. */
    public const string SIGNED_IN = 'keyring.signed_in_level';

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
        $this->session->put(static::SIGNED_IN, Assurance::of($verifications)->value);
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
        $verifications = $this->recorded();
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
        return $this->since($this->countsFrom($level));
    }

    /**
     * Why the level the session signed in at no longer holds, if it
     * doesn't and sessions.end_on_lapse is on: "idle" past its idle limit,
     * "expired" past its overall one. NIST SP 800-63B-4 (Sec. 5.2) ends a
     * session when either passes. Proving every factor for the level again
     * in time starts both over, as reauthenticating does there.
     *
     * A level a step-up reached later lapses on its own and takes nothing
     * with it, and an authenticator removed since doesn't end the sessions
     * it signed in: only time does.
     *
     * @return 'idle'|'expired'|null
     */
    public function lapse(): ?string
    {
        $level = $this->signedInLevel();

        if (! $this->endsOnLapse()) {
            return null;
        }

        $from = $this->countsFrom($level);

        if (Requirement::for($level)->isMetBy(array_values(array_filter($this->recorded(), fn (Verification $verification) => $verification->at >= $from)))) {
            return null;
        }

        return $from > now()->getTimestamp() - $this->sessions->absolute($level) ? 'idle' : 'expired';
    }

    /**
     * The level this session signed in at. None for one Keyring didn't sign
     * in itself, such as a session an app started with Auth::login().
     */
    public function signedInLevel(): Assurance
    {
        return Assurance::tryFrom((int) $this->session->get(static::SIGNED_IN, 0)) ?? Assurance::None;
    }

    /**
     * Whether this session is one sessions.end_on_lapse ends once the level
     * it signed in at has gone.
     */
    public function endsOnLapse(): bool
    {
        return config('keyring.sessions.end_on_lapse') && $this->signedInLevel() !== Assurance::None;
    }

    /**
     * The moment a verification must be no older than to count toward a
     * level: its overall limit ago, or when inactivity last lapsed it.
     */
    protected function countsFrom(Assurance $level): int
    {
        return max(
            now()->getTimestamp() - $this->sessions->absolute($level),
            $this->session->get(static::LAPSED, [])[$level->value] ?? 0,
        );
    }

    /**
     * Everything recorded, whether or not its authenticator is still there.
     *
     * @return list<Verification>
     */
    protected function recorded(): array
    {
        return array_map(Verification::fromArray(...), array_values($this->session->get(static::KEY, [])));
    }

    /**
     * Forget everything proved this session, including a confirmation in
     * progress and the marker that keeps Laravel's own password.confirm
     * middleware satisfied.
     */
    public function flush(): void
    {
        $this->session->forget([static::KEY, static::LAPSED, static::SIGNED_IN, AttemptStore::key(Purpose::Confirm), 'auth.password_confirmed_at']);
    }
}
