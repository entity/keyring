<?php

declare(strict_types=1);

namespace Keyring\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Keyring\Enrollment\Enrollment;
use Keyring\Models\Authenticator;

/**
 * A factor users can add themselves. Enrolling is always two steps: begin
 * (show a QR code, send a code, ask the browser for a credential) and
 * confirm (prove it works). Nothing is stored until it's confirmed.
 */
interface Enrollable extends Factor
{
    public function beginEnrollment(Authenticatable&Model $user, Request $request): Enrollment;

    /**
     * @return array<string, mixed>
     */
    public function enrollmentRules(): array;

    /**
     * Returns an unsaved authenticator, or null when the proof is wrong.
     */
    public function confirmEnrollment(Authenticatable&Model $user, Enrollment $enrollment, Request $request): ?Authenticator;

    /**
     * Whether a user may have more than one. When not, confirming a new one
     * replaces the old (like regenerating recovery codes).
     */
    public function multiple(): bool;
}
