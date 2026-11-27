<?php

declare(strict_types=1);

namespace Keyring\Enums;

/**
 * Why an impersonation ended (ImpersonationEnded). It ends back in the
 * impersonator's own session for Stopped, Expired and Ended, as long as
 * that session is still good: otherwise the browser is signed out, and the
 * reason is ImpersonatorSessionEnded, or Lost.
 */
enum ImpersonationEndReason: string
{
    /** The impersonator stopped it. */
    case Stopped = 'stopped';

    /** It was on for impersonation.lifetime, or its session idled out. */
    case Expired = 'expired';

    /**
     * Its session was ended some other way: by the user from their sessions
     * list, by signing out everywhere, a password change, a risk response,
     * the user no longer being allowed to sign in, or the impersonator no
     * longer being allowed to impersonate them.
     */
    case Ended = 'ended';

    /**
     * The impersonator's own session has ended (revoked, timed out), or the
     * impersonator was deleted, is no longer allowed to sign in, or is held
     * for a new password, so there was nobody to go back to and the browser
     * was signed out.
     */
    case ImpersonatorSessionEnded = 'impersonator_session_ended';

    /**
     * The browser's session no longer held the impersonation it started:
     * the user can no longer be loaded (deleted, say), someone else is
     * signed in on it, or it lost what was parked. Nothing says it's still
     * the impersonator's, so the browser was signed out.
     */
    case Lost = 'lost';

    /**
     * The browser signed out while impersonating, or someone signed in on
     * a session still holding an impersonation.
     */
    case SignedOut = 'signed_out';

    /**
     * Whether the impersonation goes back to the impersonator's session,
     * when that's still good.
     */
    public function returns(): bool
    {
        return in_array($this, [self::Stopped, self::Expired, self::Ended], true);
    }
}
