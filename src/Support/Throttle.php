<?php

namespace Keyring\Support;

use Illuminate\Validation\ValidationException;

final class Throttle
{
    /**
     * Refuse with Laravel's "too many attempts" message on the field, as a 429.
     *
     * @throws ValidationException
     */
    public static function fail(string $field, int $seconds): never
    {
        throw ValidationException::withMessages([
            $field => __('auth.throttle', ['seconds' => $seconds, 'minutes' => (int) ceil($seconds / 60)]),
        ])->status(429);
    }
}
