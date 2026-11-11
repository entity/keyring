<?php

declare(strict_types=1);

namespace Keyring\Login;

use Illuminate\Container\Attributes\Scoped;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Keyring\Enums\Purpose;
use Keyring\Exceptions\AttemptExpired;
use Keyring\Facades\Keyring;
use Keyring\Support\EncryptedSession;
use TypeError;
use ValueError;

/**
 * Keeps attempts in the session, one per purpose.
 */
#[Scoped]
class AttemptStore
{
    public function __construct(
        protected EncryptedSession $session,
    ) {}

    /**
     * @param  list<Verification>  $verifications
     */
    public function start(
        Purpose $purpose,
        Authenticatable&Model $user,
        bool $remember = false,
        ?Requirement $requirement = null,
        array $verifications = [],
    ): Attempt {
        return tap(Attempt::start($purpose, $user, $remember, $requirement, $verifications), $this->save(...));
    }

    /**
     * The attempt in progress, unless it expired, it started under another
     * guard, a confirmation isn't the signed-in user's, its user is gone or
     * no longer allowed to sign in, or their password or email address
     * changed since it was saved. A reset or change elsewhere ends every
     * half-finished sign in, including one that already got past the old
     * password, and so does an email change or its undo: a code may have
     * gone to the address the account no longer has.
     */
    public function current(Purpose $purpose): ?Attempt
    {
        $data = $this->session->get(static::key($purpose));

        try {
            $attempt = $data === null ? null : Attempt::fromArray($data);
        } catch (TypeError|ValueError) {
            $attempt = null;
        }

        if ($attempt === null || ! $this->stillStands($purpose, $attempt, $data['credentials'] ?? null)) {
            $this->forget($purpose);

            return null;
        }

        return $attempt;
    }

    public function save(Attempt $attempt): void
    {
        $this->session->put(static::key($attempt->purpose), [
            ...$attempt->toArray(),
            'credentials' => $this->credentials($attempt->user()),
        ]);
    }

    public function forget(Purpose $purpose): void
    {
        $this->session->forget(static::key($purpose));
    }

    protected function stillStands(Purpose $purpose, Attempt $attempt, mixed $credentials): bool
    {
        try {
            return ! $attempt->expired
                && $attempt->guard === config('keyring.guard')
                && ($purpose === Purpose::Login || $this->isSignedIn($attempt))
                && is_string($credentials)
                && hash_equals($credentials, $this->credentials($attempt->user()))
                && $attempt->keepsItsAuthenticators()
                && Keyring::allowsSignIn($attempt->user());
        } catch (AttemptExpired) {
            return false;
        }
    }

    /**
     * Whether the attempt's user is the one signed in. IDs are compared as
     * strings: one may be an integer and the other a string of it, and a
     * loose comparison would also take "01" or "1e0" for 1.
     */
    protected function isSignedIn(Attempt $attempt): bool
    {
        $id = auth()->guard($attempt->guard)->id();

        return $id !== null && (string) $attempt->userId === (string) $id;
    }

    /**
     * Stands in for the user's password hash and email address. It's taken
     * on every save, so the rehash that can follow a successful password
     * check doesn't count as a change.
     */
    protected function credentials(Authenticatable&Model $user): string
    {
        return hash('sha256', $user->getAuthPassword().'|'.Keyring::normalizeUsername((string) $user->getAttribute(Keyring::email())));
    }

    public static function key(Purpose $purpose): string
    {
        return 'keyring.attempt.'.$purpose->value;
    }
}
