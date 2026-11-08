<?php

namespace Keyring\Login;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Crypt;
use Keyring\Enums\Purpose;

/**
 * Keeps attempts in the session, one per purpose.
 */
class AttemptStore
{
    public function __construct(
        protected Session $session,
    ) {}

    public function start(Purpose $purpose, Authenticatable&Model $user, bool $remember = false): Attempt
    {
        return tap(Attempt::start($purpose, $user, $remember), $this->save(...));
    }

    public function current(Purpose $purpose): ?Attempt
    {
        $payload = $this->session->get($this->key($purpose));

        if (! is_string($payload)) {
            return null;
        }

        try {
            $attempt = Attempt::fromArray(json_decode(Crypt::decryptString($payload), true, flags: JSON_THROW_ON_ERROR));
        } catch (DecryptException|\JsonException|\TypeError|\ValueError) {
            $this->forget($purpose);

            return null;
        }

        if ($attempt->expired) {
            $this->forget($purpose);

            return null;
        }

        return $attempt;
    }

    public function save(Attempt $attempt): void
    {
        $this->session->put(
            $this->key($attempt->purpose),
            Crypt::encryptString(json_encode($attempt->toArray(), JSON_THROW_ON_ERROR)),
        );
    }

    public function forget(Purpose $purpose): void
    {
        $this->session->forget($this->key($purpose));
    }

    protected function key(Purpose $purpose): string
    {
        return 'keyring.attempt.'.$purpose->value;
    }
}
