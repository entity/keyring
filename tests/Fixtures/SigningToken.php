<?php

declare(strict_types=1);

namespace Keyring\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Keyring\Contracts\Enrollable;
use Keyring\Enrollment\Enrollment;
use Keyring\Enums\Category;
use Keyring\Factors\Factor;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Support\Input;

/**
 * A custom factor that signs the challenge it's given, bound to the site
 * the way a key is, and that a user has one of at a time.
 */
class SigningToken extends Factor implements Enrollable
{
    public function key(): string
    {
        return 'token';
    }

    public function categories(Authenticator $authenticator): array
    {
        return [Category::Possession];
    }

    public function phishingResistant(Authenticator $authenticator): bool
    {
        return true;
    }

    public function multiple(): bool
    {
        return false;
    }

    public function challenge(Attempt $attempt, Authenticator $authenticator): array
    {
        $nonce = Str::random(32);
        $attempt->put($this->key(), 'nonce', $nonce);

        return ['nonce' => $nonce];
    }

    public function rules(): array
    {
        return ['signature' => ['required', 'string']];
    }

    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        $nonce = $attempt->state($this->key(), 'nonce');
        $attempt->forget($this->key());

        return is_string($nonce) && hash_equals(static::sign((string) $authenticator->secret, $nonce), (string) Input::get($request, 'signature'))
            ? $this->verified($authenticator)
            : null;
    }

    public static function sign(string $secret, string $nonce): string
    {
        return hash_hmac('sha256', $nonce, $secret);
    }

    public function beginEnrollment(Authenticatable&Model $user, Request $request): Enrollment
    {
        $secret = Str::random(32);

        return Enrollment::make($this->key(), ['secret' => $secret], ['secret' => $secret]);
    }

    public function enrollmentRules(): array
    {
        return [];
    }

    public function confirmEnrollment(Authenticatable&Model $user, Enrollment $enrollment, Request $request): ?Authenticator
    {
        return $this->makeAuthenticator(['name' => 'Token', 'secret' => $enrollment->state('secret')]);
    }
}
