<?php

namespace Keyring\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Keyring\Contracts\Enrollable;
use Keyring\Contracts\SendsCodes;
use Keyring\Enrollment\Enrollment;
use Keyring\Enrollment\EnrollmentStore;
use Keyring\Enums\Category;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;

/**
 * Base for factors that send a one-time code (email, SMS, ...). Handles the
 * OWASP rules once: random codes, short expiry, single use, limited guesses,
 * resend replaces the old code, stored hashed, never logged.
 *
 * A new factor only needs key(), deliver() and defaultName().
 */
abstract class CodeFactor extends Factor implements Enrollable, SendsCodes
{
    /** Digits in each code. */
    protected int $length = 8;

    /** Seconds a code stays valid. */
    protected int $ttl = 600;

    /** Wrong guesses allowed per code. */
    protected int $maxGuesses = 5;

    /**
     * Send the code to the user. Never log it.
     */
    abstract protected function deliver(Authenticatable&Model $user, Authenticator $authenticator, string $code): void;

    /**
     * The default name for a new authenticator of this factor.
     */
    abstract protected function defaultName(Authenticatable&Model $user): string;

    public function categories(Authenticator $authenticator): array
    {
        return [Category::Possession];
    }

    public function priority(): int
    {
        return 30;
    }

    public function rules(): array
    {
        return ['code' => ['required', 'string', 'max:32']];
    }

    public function send(Attempt $attempt, Authenticator $authenticator): void
    {
        $code = $this->generate();

        $attempt->put($this->key(), 'code', $this->issue($code, $authenticator));

        $this->deliver($attempt->user(), $authenticator, $code);
    }

    public function challenge(Attempt $attempt, Authenticator $authenticator): array
    {
        $issued = $attempt->state($this->key(), 'code');

        return [
            'length' => $this->length,
            'sent' => $issued !== null,
            'expiresAt' => $issued === null ? null : date(DATE_ATOM, $issued['expires_at']),
        ];
    }

    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        $issued = $attempt->state($this->key(), 'code');

        // A code only proves the authenticator it was sent to.
        if (($issued['authenticator'] ?? null) !== $authenticator->getKey()) {
            $issued = null;
        }

        [$valid, $issued] = $this->check($issued, (string) $request->input('code'));

        $issued === null
            ? $attempt->forget($this->key(), 'code')
            : $attempt->put($this->key(), 'code', $issued);

        return $valid ? $this->verified($authenticator) : null;
    }

    public function beginEnrollment(Authenticatable&Model $user, Request $request): Enrollment
    {
        $code = $this->generate();
        $authenticator = $this->newAuthenticator($user, $request);

        $this->deliver($user, $authenticator, $code);

        return Enrollment::make($this->key(), [
            'length' => $this->length,
            'sent' => true,
        ], [
            'code' => $this->issue($code),
            'name' => $authenticator->name,
            'secret' => $authenticator->secret,
            'meta' => $authenticator->meta,
        ]);
    }

    public function confirmEnrollment(Authenticatable&Model $user, Enrollment $enrollment, Request $request): ?Authenticator
    {
        [$valid, $issued] = $this->check($enrollment->state('code'), (string) $request->input('code'));

        if (! $valid) {
            // Keep the guess count, or enrollment codes could be guessed forever.
            app(EnrollmentStore::class)->put($enrollment->with('code', $issued));

            return null;
        }

        return $this->makeAuthenticator([
            'name' => $this->nameFrom($request, $enrollment->state('name')),
            'secret' => $enrollment->state('secret'),
            'meta' => $enrollment->state('meta'),
        ]);
    }

    /**
     * The authenticator a new enrollment will create. Override to collect a
     * phone number or similar: put it in `secret` (encrypted) or `meta`.
     */
    protected function newAuthenticator(Authenticatable&Model $user, Request $request): Authenticator
    {
        $authenticator = $this->makeAuthenticator(['name' => $this->nameFrom($request, $this->defaultName($user))]);

        return $authenticator->setRelation('authenticatable', $user);
    }

    protected function generate(): string
    {
        return str_pad((string) random_int(0, 10 ** $this->length - 1), $this->length, '0', STR_PAD_LEFT);
    }

    /**
     * @return array{hash: string, expires_at: int, guesses: int, authenticator: ?string}
     */
    protected function issue(string $code, ?Authenticator $authenticator = null): array
    {
        return [
            'hash' => $this->hash($code),
            'expires_at' => now()->addSeconds($this->ttl)->getTimestamp(),
            'guesses' => 0,
            'authenticator' => $authenticator?->getKey(),
        ];
    }

    /**
     * @param  array{hash: string, expires_at: int, guesses: int, authenticator?: ?string}|null  $issued
     * @return array{0: bool, 1: array{hash: string, expires_at: int, guesses: int, authenticator?: ?string}|null}
     */
    protected function check(?array $issued, string $code): array
    {
        if ($issued === null || $issued['expires_at'] < now()->getTimestamp() || $issued['guesses'] >= $this->maxGuesses) {
            return [false, null];
        }

        if (hash_equals($issued['hash'], $this->hash($this->normalizeCode($code)))) {
            return [true, null];
        }

        $issued['guesses']++;

        return [false, $issued['guesses'] >= $this->maxGuesses ? null : $issued];
    }

    protected function hash(string $code): string
    {
        return hash_hmac('sha256', $this->key().'|'.$code, config('app.key'));
    }
}
