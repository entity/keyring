<?php

namespace Keyring\Contracts;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Keyring\Enums\Category;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;

/**
 * A way of proving identity. Every factor shares this contract, so adding one
 * never needs new routes, controllers or tables.
 */
interface Factor
{
    /**
     * The unique key, used in routes and the authenticators table.
     */
    public function key(): string;

    /**
     * The categories this authenticator is expected to provide. Used to plan
     * which factors to offer. The categories actually counted come from the
     * Verification returned by verify().
     *
     * @return list<Category>
     */
    public function categories(Authenticator $authenticator): array;

    /**
     * Whether a verification is bound to the site's origin (WebAuthn).
     */
    public function phishingResistant(Authenticator $authenticator): bool;

    /**
     * Whether the secret can't leave the device it's on, e.g. a security key
     * or a passkey that isn't synced. Only these reach AAL3.
     */
    public function deviceBound(Authenticator $authenticator): bool;

    /**
     * Higher priority factors are offered first.
     */
    public function priority(): int;

    /**
     * The user's authenticators for this factor.
     *
     * @param  Collection<int, Authenticator>  $stored  the user's confirmed, stored authenticators
     * @return Collection<int, Authenticator>
     */
    public function authenticators(Authenticatable&Model $user, Collection $stored): Collection;

    /**
     * Props for the challenge page. Must be safe to call repeatedly.
     *
     * @return array<string, mixed>
     */
    public function challenge(Attempt $attempt, Authenticator $authenticator): array;

    /**
     * Validation rules for a verification request.
     *
     * @return array<string, mixed>
     */
    public function rules(): array;

    /**
     * Check the proof in the request. Returns null when it doesn't match.
     */
    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification;

    /**
     * Rate limits for verifying this factor.
     *
     * @return list<Limit>
     */
    public function limits(Request $request, ?Attempt $attempt): array;

    /**
     * The form field that failures are reported on.
     */
    public function errorKey(): string;

    /**
     * How this authenticator is shown in "try another way".
     *
     * @return array<string, mixed>
     */
    public function present(Authenticator $authenticator): array;
}
