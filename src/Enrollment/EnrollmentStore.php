<?php

namespace Keyring\Enrollment;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Crypt;

/**
 * Keeps in-progress enrollments in the session, one per factor.
 */
class EnrollmentStore
{
    public function __construct(
        protected Session $session,
    ) {}

    public function put(Enrollment $enrollment): void
    {
        $this->session->put(
            $this->key($enrollment->factor),
            Crypt::encryptString(json_encode($enrollment->toArray(), JSON_THROW_ON_ERROR)),
        );
    }

    public function get(string $factor): ?Enrollment
    {
        $payload = $this->session->get($this->key($factor));

        try {
            $enrollment = is_string($payload)
                ? Enrollment::fromArray(json_decode(Crypt::decryptString($payload), true, flags: JSON_THROW_ON_ERROR))
                : null;
        } catch (DecryptException|\JsonException|\TypeError) {
            $enrollment = null;
        }

        if ($enrollment?->expired()) {
            $this->forget($factor);

            return null;
        }

        return $enrollment;
    }

    public function forget(string $factor): void
    {
        $this->session->forget($this->key($factor));
    }

    protected function key(string $factor): string
    {
        return 'keyring.enrollment.'.$factor;
    }
}
