<?php

declare(strict_types=1);

namespace Keyring\Support;

use Illuminate\Container\Attributes\Scoped;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Crypt;
use JsonException;

/**
 * Keeps half-finished work (a login waiting for its second factor, an
 * authenticator being set up) in the session as encrypted JSON, never
 * serialize(). Encrypted even where the session already is, so a session
 * store that leaks doesn't give away a pending secret.
 *
 * Scoped, since it wraps the current session.
 */
#[Scoped]
class EncryptedSession
{
    public function __construct(
        protected Session $session,
    ) {}

    /**
     * @param  array<string, mixed>  $data
     */
    public function put(string $key, array $data): void
    {
        $this->session->put($key, Crypt::encryptString(json_encode($data, JSON_THROW_ON_ERROR)));
    }

    /**
     * What was put under the key, or null when there's nothing there or it
     * can't be read back (APP_KEY changed, or it isn't Keyring's).
     *
     * @return array<string, mixed>|null
     */
    public function get(string $key): ?array
    {
        $payload = $this->session->get($key);

        if (! is_string($payload)) {
            return null;
        }

        try {
            $data = json_decode(Crypt::decryptString($payload), true, flags: JSON_THROW_ON_ERROR);
        } catch (DecryptException|JsonException) {
            return null;
        }

        return is_array($data) ? $data : null;
    }

    public function forget(string $key): void
    {
        $this->session->forget($key);
    }
}
