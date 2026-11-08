<?php

namespace Keyring\Login;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Crypt;
use Keyring\Enums\Purpose;
use Keyring\Exceptions\AttemptExpired;

/**
 * Keeps attempts in the session, one per purpose.
 */
class AttemptStore
{
    public function __construct(
        protected Session $session,
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
     * guard, its user is gone, or their password changed since it was saved:
     * a reset or change elsewhere ends every half-finished sign in, including
     * one that already got past the old password.
     */
    public function current(Purpose $purpose): ?Attempt
    {
        $payload = $this->session->get($this->key($purpose));

        if (! is_string($payload)) {
            return null;
        }

        try {
            $data = json_decode(Crypt::decryptString($payload), true, flags: JSON_THROW_ON_ERROR);
            $attempt = Attempt::fromArray($data);
            $valid = ! $attempt->expired
                && $attempt->guard === config('keyring.guard')
                && hash_equals($data['password'] ?? '', $this->passwordHash($attempt->user()));
        } catch (AttemptExpired|DecryptException|\JsonException|\TypeError|\ValueError) {
            $valid = false;
        }

        if (! $valid) {
            $this->forget($purpose);

            return null;
        }

        return $attempt;
    }

    public function save(Attempt $attempt): void
    {
        $this->session->put(
            $this->key($attempt->purpose),
            Crypt::encryptString(json_encode([
                ...$attempt->toArray(),
                'password' => $this->passwordHash($attempt->user()),
            ], JSON_THROW_ON_ERROR)),
        );
    }

    public function forget(Purpose $purpose): void
    {
        $this->session->forget($this->key($purpose));
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

    protected function key(Purpose $purpose): string
    {
        return 'keyring.attempt.'.$purpose->value;
    }
}
