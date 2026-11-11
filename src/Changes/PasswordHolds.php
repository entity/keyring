<?php

namespace Keyring\Changes;

use Illuminate\Container\Attributes\Scoped;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Keyring\Events\PasswordChangeRequired;
use Keyring\Models\PasswordHold;

/**
 * Users held until they choose a new password. NIST SP 800-63B-4 (Sec.
 * 3.1.1.2) never has passwords changed on a schedule, and always has one
 * changed when there's evidence it was compromised.
 *
 * A hold is a row, not something in the session or the cache, so signing
 * out and in again doesn't shake it off and clearing the cache doesn't lift
 * it. Only a new password does, however it's set: a change, or a reset.
 */
#[Scoped]
class PasswordHolds
{
    /** Who a session last found without a hold, and when, to look again later. */
    public const string CLEAR = 'keyring.password_hold_clear';

    /** Seconds a session goes on trusting that there was no hold. */
    protected const int RECHECK = 60;

    public function __construct(
        protected Session $session,
    ) {}

    /**
     * Hold the user until their password changes. Returns whether they're
     * held: an account with no password has nothing to change, and a hold
     * on one would only lock it out.
     */
    public function place(Authenticatable&Model $user, ?string $reason = null): bool
    {
        if (blank($user->getAuthPassword())) {
            return false;
        }

        // This request's session may just have been told there was none.
        $this->session->forget(static::CLEAR);

        // One hold is enough, however often the evidence turns up, and two
        // requests finding it at once make one between them.
        $hold = PasswordHold::query()->firstOrCreate(
            ['authenticatable_type' => $user->getMorphClass(), 'authenticatable_id' => $user->getKey()],
            ['reason' => $reason],
        );

        if ($hold->wasRecentlyCreated) {
            PasswordChangeRequired::dispatch($user, $reason);
        }

        return true;
    }

    public function holds(Authenticatable&Model $user): bool
    {
        return filled($user->getAuthPassword()) && $this->query($user)->exists();
    }

    /**
     * Whether the signed-in user is held, asked on every request. The
     * answer "no" is kept in the session for a minute, so a signed-in page
     * view isn't a query each time. A hold placed from elsewhere reaches a
     * session within that minute; "yes" is asked again every time, so the
     * session is let go the moment the password changes.
     */
    public function holdsSession(Authenticatable&Model $user): bool
    {
        $clear = $this->session->get(static::CLEAR);
        $now = now()->getTimestamp();

        if (is_array($clear) && ($clear['user'] ?? null) === $user->getAuthIdentifier() && $now - ($clear['at'] ?? 0) < static::RECHECK) {
            return false;
        }

        if ($this->holds($user)) {
            return true;
        }

        $this->session->put(static::CLEAR, ['user' => $user->getAuthIdentifier(), 'at' => $now]);

        return false;
    }

    /**
     * Why the user is held, if a reason was given.
     */
    public function reason(Authenticatable&Model $user): ?string
    {
        return $this->query($user)->value('reason');
    }

    /**
     * Let the user go: their password changed, or the hold was a mistake.
     */
    public function lift(Authenticatable&Model $user): void
    {
        $this->query($user)->delete();
    }

    /**
     * @return Builder<PasswordHold>
     */
    protected function query(Authenticatable&Model $user): Builder
    {
        return PasswordHold::query()->ownedBy($user);
    }
}
