<?php

declare(strict_types=1);

namespace Keyring\Login;

use Illuminate\Auth\Events\Verified;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Keyring\Events\Authenticated;
use Keyring\Events\PasswordReset;
use Keyring\KeyringManager;

/**
 * A verification link followed by a browser that isn't signed in, which is
 * how every new user arrives when registration hides who has an account:
 * until their address is verified they can't sign in at all.
 *
 * The link alone verifies nothing. It lets this browser sign in to that one
 * account, and signing in is what verifies the address. So it takes the
 * mailbox and the password together, as it does when a signed-in user
 * follows the link: the owner of an address someone else registered can't
 * verify an account they don't have the password to, and whoever registered
 * it never sees the link.
 */
class VerificationLink
{
    public const string KEY = 'keyring.verifying';

    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    /**
     * Keep a link whose signature has been checked, for as long as it's good,
     * under a new session ID: one only the browser that followed it holds,
     * whoever else had the ID it came with.
     */
    public function remember(Request $request, string $id, string $hash): void
    {
        $request->session()->regenerate(true);
        $request->session()->put(self::KEY, ['id' => $id, 'hash' => $hash, 'expires' => $request->integer('expires')]);
    }

    /**
     * Whether this browser followed the link sent to the user's address.
     */
    public function followedFor(Authenticatable&Model $user): bool
    {
        // The current request, not one captured at boot (Octane).
        $request = request();
        $link = $request->hasSession() ? $request->session()->get(self::KEY) : null;

        return $user instanceof MustVerifyEmail
            && is_array($link)
            && hash_equals((string) $user->getKey(), (string) ($link['id'] ?? ''))
            && hash_equals(sha1($user->getEmailForVerification()), (string) ($link['hash'] ?? ''))
            && (int) ($link['expires'] ?? 0) >= now()->getTimestamp();
    }

    /**
     * Signing in from a browser that followed the link verifies the address.
     */
    public function signedIn(Authenticated $event): void
    {
        if ($this->keyring->hidesRegisteredAddresses() && $event->user instanceof Model && $this->followedFor($event->user)) {
            $this->verify($event->user);

            request()->session()->forget(self::KEY);
        }
    }

    /**
     * A reset link went to the address too, so finishing one proves it like
     * the verification link does. Without this, the owner of an address
     * someone else registered could reset its password and still not sign in.
     */
    public function passwordReset(PasswordReset $event): void
    {
        if ($this->keyring->hidesRegisteredAddresses()) {
            $this->verify($event->user);
        }
    }

    protected function verify(Authenticatable $user): void
    {
        if ($user instanceof MustVerifyEmail && ! $user->hasVerifiedEmail() && $user->markEmailAsVerified()) {
            event(new Verified($user));
        }
    }
}
