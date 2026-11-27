<?php

declare(strict_types=1);

namespace Keyring\Enums;

/**
 * Why an impersonation ended (ImpersonationEnded). It ends back in the
 * impersonator's own session for every reason but the last two, as long as
 * that session is still good: otherwise the browser is signed out, and the
 * reason is ImpersonatorSessionEnded.
 */
enum ImpersonationEndReason: string
{
    /** The impersonator stopped it. */
    case Stopped = 'stopped';

    /** It was on for impersonation.lifetime. */
    case Expired = 'expired';

    /**
     * Its session was ended some other way: by the user from their sessions
     * list, by signing out everywhere, a password change, a risk response,
     * or the user no longer being allowed to sign in.
     */
    case Ended = 'ended';

    /**
     * The impersonator's own session has ended (revoked, timed out), or the
     * impersonator was deleted or is no longer allowed to sign in, so there
     * was nobody to go back to and the browser was signed out.
     */
    case ImpersonatorSessionEnded = 'impersonator_session_ended';

    /** The browser signed out while impersonating. */
    case SignedOut = 'signed_out';

    /**
     * Whether the impersonation goes back to the impersonator's session,
     * when that's still good.
     */
    public function returns(): bool
    {
        return $this !== self::SignedOut && $this !== self::ImpersonatorSessionEnded;
    }
}
