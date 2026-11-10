<?php

namespace Keyring\Enrollment;

use Illuminate\Container\Attributes\Scoped;
use Keyring\Support\EncryptedSession;
use TypeError;

/**
 * Keeps in-progress enrollments in the session, one per factor.
 */
#[Scoped]
class EnrollmentStore
{
    public function __construct(
        protected EncryptedSession $session,
    ) {}

    public function put(Enrollment $enrollment): void
    {
        $this->session->put($this->key($enrollment->factor), $enrollment->toArray());
    }

    public function get(string $factor): ?Enrollment
    {
        $data = $this->session->get($this->key($factor));

        try {
            $enrollment = $data === null ? null : Enrollment::fromArray($data);
        } catch (TypeError) {
            $enrollment = null;
        }

        if ($enrollment?->expired) {
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
