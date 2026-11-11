<?php

namespace Keyring\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Keyring\Contracts\Enrollable;
use Keyring\Contracts\SendsCodes;
use Keyring\Enrollment\Enrollment;
use Keyring\Enums\Category;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Support\Duration;
use Keyring\Support\KeyedHash;
use LogicException;

/**
 * Base for factors that send a one-time code (email, SMS, ...). Handles the
 * rules once: random codes, short expiry, single use, limited guesses,
 * resend replaces the old code, stored hashed, never logged.
 *
 * A code's state is kept on the server (SentCodes), not in the session, so
 * those rules hold on any session driver.
 *
 * A new factor only needs key(), deliver() and defaultName().
 */
abstract class CodeFactor extends Factor implements Enrollable, SendsCodes
{
    /** The fewest digits a code may have: about 20 bits, the least OWASP ASVS 6.5.4 accepts. */
    public const int MIN_LENGTH = 6;

    /** The longest a code may last, in seconds: the ten minutes OWASP ASVS 6.5.5 allows. */
    public const int MAX_TTL = 600;

    /** Digits in each code, MIN_LENGTH or more. */
    protected int $length = 8;

    /** Seconds a code stays valid, MAX_TTL at most. */
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

    /**
     * Refuse a code too short to resist guessing, or one that outlives its
     * ten minutes. Checked when the factor is registered, so a subclass that
     * sets either too far fails as the app starts using its factors, not
     * quietly at someone's sign in.
     *
     * @throws LogicException
     */
    public function ensureCodesAreSafe(): void
    {
        throw_if($this->length < self::MIN_LENGTH, LogicException::class, sprintf(
            'The [%s] factor sends %d digit codes. Keyring refuses codes shorter than %d digits: fewer are too easy to guess (OWASP ASVS 6.5.4).',
            $this->key(), $this->length, self::MIN_LENGTH,
        ));

        throw_if($this->ttl < 1 || $this->ttl > self::MAX_TTL, LogicException::class, sprintf(
            'The [%s] factor keeps its codes for %d seconds. Keyring refuses a code that lasts longer than %d seconds, or no time at all: a sent code has ten minutes at most (OWASP ASVS 6.5.5).',
            $this->key(), $this->ttl, self::MAX_TTL,
        ));
    }

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
        $owner = $this->attemptCodes($attempt);

        // Out of guesses, another code is one nobody could use. The attempt
        // may be an earlier copy of the session's, from before they ran out.
        if ($this->codes()->guesses($owner) >= $this->maxGuesses) {
            $attempt->exhausted = true;

            return;
        }

        $code = $this->generate();

        $this->codes()->replace($owner, $this->issue($code, (string) $authenticator->getKey()));

        $this->deliver($attempt->user(), $authenticator, $code);
    }

    public function challenge(Attempt $attempt, Authenticator $authenticator): array
    {
        $issued = $this->codes()->current($this->attemptCodes($attempt));

        return [
            'length' => $this->length,
            'sent' => $issued !== null,
            'expiresAt' => $issued === null ? null : date(DATE_ATOM, $issued['expires_at']),
        ];
    }

    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        $owner = $this->attemptCodes($attempt);
        $sent = $this->codes()->current($owner);

        // A code only proves the authenticator it was sent to, and a guess
        // aimed at another one leaves it be.
        $ours = ($sent['for'] ?? null) === (string) $authenticator->getKey();

        // The count lasts as long as the attempt can.
        ['valid' => $valid, 'guesses' => $guesses] = $this->check($owner, $ours ? $sent : null, (string) $request->input('code'), $attempt->expiresAt - now()->getTimestamp());

        if ($guesses >= $this->maxGuesses) {
            $attempt->exhausted = true;
        }

        return $valid ? $this->verified($authenticator) : null;
    }

    public function beginEnrollment(Authenticatable&Model $user, Request $request): Enrollment
    {
        $owner = $this->enrollmentCodes($user);

        // Starting again keeps the count, or a new code would mean new guesses.
        if ($this->codes()->guesses($owner) >= $this->maxGuesses) {
            throw $this->tooManyEnrollmentGuesses();
        }

        $code = $this->generate();
        $authenticator = $this->newAuthenticator($user, $request);
        $reference = Str::random(40);

        $this->codes()->replace($owner, $this->issue($code, $reference));

        $this->deliver($user, $authenticator, $code);

        return Enrollment::make($this->key(), [
            'length' => $this->length,
            'sent' => true,
        ], [
            'reference' => $reference,
            'name' => $authenticator->name,
            'secret' => $authenticator->secret,
            'meta' => $authenticator->meta,
        ]);
    }

    public function confirmEnrollment(Authenticatable&Model $user, Enrollment $enrollment, Request $request): ?Authenticator
    {
        $owner = $this->enrollmentCodes($user);
        $sent = $this->codes()->current($owner);

        // A code only confirms the enrollment it was sent for. The name and
        // the number to enroll are this session's, and may be from an
        // enrollment started before the one the code went out for.
        $ours = is_string($sent['for'] ?? null) && $sent['for'] === $enrollment->state('reference');

        ['valid' => $valid, 'guesses' => $guesses] = $this->check($owner, $ours ? $sent : null, (string) $request->input('code'), Duration::seconds(config('keyring.enrollments.keep_for')));

        if (! $valid) {
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
     * What's kept of a code just made: its hash, when it expires, and what
     * it was sent for (an authenticator's ID, or an enrollment's reference).
     *
     * @return array{hash: string, expires_at: int, for: ?string}
     */
    protected function issue(#[\SensitiveParameter] string $code, ?string $for = null): array
    {
        return [
            'hash' => $this->hash($code),
            'expires_at' => now()->addSeconds($this->ttl)->getTimestamp(),
            'for' => $for,
        ];
    }

    /**
     * Check a guess at the code sent for the owner: whether it's valid, and
     * the wrong guesses so far. A code that's right is used up here, on the
     * server, so it can't be typed a second time whatever the session says
     * and whatever becomes of this sign in. One that has run out of guesses
     * is dropped.
     *
     * The guesses are counted apart from the code, because the count has to
     * outlive it: a code can expire or be replaced, the count carries on,
     * for the given seconds from the first wrong guess.
     *
     * @param  array{hash: string, expires_at: int, for: ?string}|null  $sent
     * @return array{valid: bool, guesses: int}
     */
    protected function check(string $owner, ?array $sent, #[\SensitiveParameter] string $code, int $seconds): array
    {
        $codes = $this->codes();
        $guesses = $codes->guesses($owner);

        if ($sent === null || $guesses >= $this->maxGuesses) {
            return ['valid' => false, 'guesses' => $guesses];
        }

        if (hash_equals($sent['hash'], $this->hash($this->normalizeCode($code)))) {
            return ['valid' => $codes->spend($owner, $sent), 'guesses' => $guesses];
        }

        $guesses = $codes->guessed($owner, $seconds);

        if ($guesses >= $this->maxGuesses) {
            $codes->forget($owner);
        }

        return ['valid' => false, 'guesses' => $guesses];
    }

    /**
     * Where a pending sign in or step-up keeps its code and its guesses. By
     * its ID, which every copy of the session that holds the attempt shares.
     */
    protected function attemptCodes(Attempt $attempt): string
    {
        return 'attempt|'.$this->key().'|'.$attempt->id;
    }

    /**
     * Where a user's enrollment of this factor keeps its code and its
     * guesses. By user, so starting again, in this session or an earlier
     * copy of it, finds the same count and replaces the same code.
     */
    protected function enrollmentCodes(Authenticatable&Model $user): string
    {
        return 'enrollment|'.$this->key().'|'.$user->getMorphClass().':'.$user->getAuthIdentifier();
    }

    /**
     * Asked for when a code is sent or typed, not when the factor is built:
     * factors are registered while the app boots, before the rate limiter's
     * cache store may exist.
     */
    protected function codes(): SentCodes
    {
        return app(SentCodes::class);
    }

    protected function tooManyEnrollmentGuesses(): ValidationException
    {
        return ValidationException::withMessages([$this->errorKey() => __('keyring::keyring.enrollment_too_many_codes')]);
    }

    protected function hash(#[\SensitiveParameter] string $code): string
    {
        return KeyedHash::make(KeyedHash::ONE_TIME_CODES, $this->key().'|'.$code);
    }
}
