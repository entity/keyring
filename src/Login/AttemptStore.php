<?php

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
     * no longer allowed to sign in, or their password changed since it was
     * saved: a reset or change elsewhere ends every half-finished sign in,
     * including one that already got past the old password.
     */
    public function current(Purpose $purpose): ?Attempt
    {
        $data = $this->session->get(static::key($purpose));

        try {
            $attempt = $data === null ? null : Attempt::fromArray($data);
        } catch (TypeError|ValueError) {
            $attempt = null;
        }

        if ($attempt === null || ! $this->stillStands($purpose, $attempt, $data['password'] ?? null)) {
            $this->forget($purpose);

            return null;
        }

        return $attempt;
    }

    public function save(Attempt $attempt): void
    {
        $this->session->put(static::key($attempt->purpose), [
            ...$attempt->toArray(),
            'password' => $this->passwordHash($attempt->user()),
        ]);
    }

    public function forget(Purpose $purpose): void
    {
        $this->session->forget(static::key($purpose));
    }

    protected function stillStands(Purpose $purpose, Attempt $attempt, mixed $passwordHash): bool
    {
        try {
            return ! $attempt->expired
                && $attempt->guard === config('keyring.guard')
                && ($purpose === Purpose::Login || $attempt->userId == auth()->guard($attempt->guard)->id())
                && is_string($passwordHash)
                && hash_equals($passwordHash, $this->passwordHash($attempt->user()))
                && Keyring::allowsSignIn($attempt->user());
        } catch (AttemptExpired) {
            return false;
        }
    }

    /**
     * Stands in for the user's password hash. It's taken on every save, so
     * the rehash that can follow a successful password check doesn't count
     * as a change.
     */
    protected function passwordHash(Authenticatable $user): string
    {
        return hash('sha256', (string) $user->getAuthPassword());
    }

    public static function key(Purpose $purpose): string
    {
        return 'keyring.attempt.'.$purpose->value;
    }
}
