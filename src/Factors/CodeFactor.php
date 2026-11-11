<?php

namespace Keyring\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Keyring\Contracts\Enrollable;
use Keyring\Contracts\SendsCodes;
use Keyring\Enrollment\Enrollment;
use Keyring\Enrollment\EnrollmentStore;
use Keyring\Enums\Category;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Support\Input;
use Keyring\Support\KeyedHash;

/**
 * Base for factors that send a one-time code (email, SMS, ...). Handles the
 * rules once: random codes, short expiry, single use, limited guesses,
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

    /** Wrong guesses allowed per sign in or enrollment, however many codes it sends. */
    protected int $maxGuesses = 5;

    /**
     * Send the code to the user. Never log it.
     */
    abstract protected function deliver(Authenticatable&Model $user, Authenticator $authenticator, #[\SensitiveParameter] string $code): void;

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
        $sent = $attempt->state($this->key(), 'code');

        // A code only proves the authenticator it was sent to, and a guess
        // aimed at another one leaves it be.
        $ours = ($sent['authenticator'] ?? null) === $authenticator->getKey();

        ['valid' => $valid, 'issued' => $issued, 'guesses' => $guesses] = $this->check($ours ? $sent : null, (string) Input::get($request, 'code'), $attempt->state($this->key(), 'guesses', 0));

        $attempt->put($this->key(), 'guesses', $guesses);

        if ($guesses >= $this->maxGuesses) {
            $attempt->exhausted = true;
        }

        if ($ours) {
            $issued === null
                ? $attempt->forget($this->key(), 'code')
                : $attempt->put($this->key(), 'code', $issued);
        }

        return $valid ? $this->verified($authenticator) : null;
    }

    public function beginEnrollment(Authenticatable&Model $user, Request $request): Enrollment
    {
        // Starting again keeps the count, or a new code would mean new guesses.
        $guesses = app(EnrollmentStore::class)->get($this->key())?->state('guesses', 0) ?? 0;

        if ($guesses >= $this->maxGuesses) {
            throw $this->tooManyEnrollmentGuesses();
        }

        $code = $this->generate();
        $authenticator = $this->newAuthenticator($user, $request);

        $this->deliver($user, $authenticator, $code);

        return Enrollment::make($this->key(), [
            'length' => $this->length,
            'sent' => true,
        ], [
            'code' => $this->issue($code),
            'guesses' => $guesses,
            'name' => $authenticator->name,
            'secret' => $authenticator->secret,
            'meta' => $authenticator->meta,
        ]);
    }

    public function confirmEnrollment(Authenticatable&Model $user, Enrollment $enrollment, Request $request): ?Authenticator
    {
        ['valid' => $valid, 'issued' => $issued, 'guesses' => $guesses] = $this->check($enrollment->state('code'), (string) Input::get($request, 'code'), $enrollment->state('guesses', 0));

        if (! $valid) {
            // Keep the guess count, or enrollment codes could be guessed forever.
            app(EnrollmentStore::class)->put($enrollment->with('code', $issued)->with('guesses', $guesses));

            if ($guesses >= $this->maxGuesses) {
                throw $this->tooManyEnrollmentGuesses();
            }

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
     * @return array{hash: string, expires_at: int, authenticator: ?string}
     */
    protected function issue(#[\SensitiveParameter] string $code, ?Authenticator $authenticator = null): array
    {
        return [
            'hash' => $this->hash($code),
            'expires_at' => now()->addSeconds($this->ttl)->getTimestamp(),
            'authenticator' => $authenticator?->getKey(),
        ];
    }

    /**
     * Check a guess at the issued code: whether it's valid, the code to keep
     * (null once it's spent, expired or out of guesses) and the guesses so
     * far. They're counted apart from the code, because the count has to
     * outlive it: a code can expire or be replaced, the count carries on.
     *
     * @param  array{hash: string, expires_at: int, authenticator?: ?string}|null  $issued
     * @return array{valid: bool, issued: array{hash: string, expires_at: int, authenticator?: ?string}|null, guesses: int}
     */
    protected function check(?array $issued, #[\SensitiveParameter] string $code, int $guesses): array
    {
        if ($issued === null || $issued['expires_at'] < now()->getTimestamp() || $guesses >= $this->maxGuesses) {
            return ['valid' => false, 'issued' => null, 'guesses' => $guesses];
        }

        if (hash_equals($issued['hash'], $this->hash($this->normalizeCode($code)))) {
            return ['valid' => true, 'issued' => null, 'guesses' => $guesses];
        }

        $guesses++;

        return ['valid' => false, 'issued' => $guesses >= $this->maxGuesses ? null : $issued, 'guesses' => $guesses];
    }

    protected function tooManyEnrollmentGuesses(): ValidationException
    {
        return ValidationException::withMessages([$this->errorKey() => __('keyring::keyring.enrollment_too_many_codes')]);
    }

    protected function hash(#[\SensitiveParameter] string $code): string
    {
        return KeyedHash::make($this->key().'|'.$code);
    }
}
