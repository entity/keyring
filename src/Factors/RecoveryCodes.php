<?php

declare(strict_types=1);

namespace Keyring\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;
use Keyring\Contracts\Enrollable;
use Keyring\Enrollment\Enrollment;
use Keyring\Enums\Category;
use Keyring\Events\RecoveryCodeUsed;
use Keyring\Facades\Keyring;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Support\Input;
use Keyring\Support\KeyedHash;
use ParagonIE\ConstantTime\Base32;

/**
 * Single-use codes the user saved when setting up their first second factor.
 * Stored as keyed hashes, never in plain text.
 *
 * A keyed hash is quick to work out, so it's only enough for a code too long
 * to guess: OWASP ASVS 5.0.0 (6.5.2) asks for 112 random bits, and a slow, salted
 * password hash for anything with fewer. So a code is only stored, and only
 * accepted, in one of two forms that have them:
 *
 * - Keyring's own: 26 base32 characters (128 bits), typed in either case.
 * - Fortify's, as keyring:import brings them in: 20 letters and digits (119
 *   bits), which only carry that much while their case counts.
 *
 * Anything else is refused when a set is stored and never matches when one
 * is typed.
 */
class RecoveryCodes extends Factor implements Enrollable
{
    public const string KEY = 'recovery';

    /** Where a set keeps when one of its codes was last used. */
    public const string USED_AT = 'code_used_at';

    public function __construct(
        protected int $count = 8,
    ) {}

    public function key(): string
    {
        return self::KEY;
    }

    /**
     * A used-up set proves nothing, so it doesn't count as a factor (or
     * users would be asked for codes they no longer have).
     */
    public function categories(Authenticator $authenticator): array
    {
        return $this->hashes($authenticator) === [] ? [] : [Category::Possession];
    }

    /**
     * Always offered last.
     */
    public function priority(): int
    {
        return 0;
    }

    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        $code = $this->canonical((string) Input::get($request, 'code'));
        $candidates = $code === null ? [] : KeyedHash::candidates(KeyedHash::RECOVERY_CODES, $code);

        $used = $this->consume($authenticator, function (Authenticator $locked) use ($candidates) {
            $hashes = $this->hashes($locked);
            $match = array_find_key($hashes, fn (string $stored) => array_any($candidates, fn (string $hash) => hash_equals($stored, $hash)));

            if ($match === null) {
                return false;
            }

            unset($hashes[$match]);
            $locked->secret = json_encode(array_values($hashes), JSON_THROW_ON_ERROR);

            // Kept on the set until a new one takes its place, so the app
            // can keep asking the user to make one.
            $locked->withMeta(static::USED_AT, now()->getTimestamp());

            return true;
        });

        if (! $used) {
            return null;
        }

        RecoveryCodeUsed::dispatch($authenticator, count($this->hashes($authenticator)));

        // The code just used proves possession, even when it was the last.
        return $this->verified($authenticator, [Category::Possession]);
    }

    /**
     * With how many codes are left, and whether one has been used, which is
     * when the user should be asked to make a new set.
     */
    public function present(Authenticator $authenticator): array
    {
        return [
            ...parent::present($authenticator),
            'remaining' => count($this->hashes($authenticator)),
            'replace' => $authenticator->meta(static::USED_AT) !== null,
        ];
    }

    public function multiple(): bool
    {
        return false;
    }

    public function beginEnrollment(Authenticatable&Model $user, Request $request): Enrollment
    {
        ['codes' => $codes, 'secret' => $secret] = $this->generate();

        return Enrollment::make($this->key(), ['codes' => $codes], ['secret' => $secret]);
    }

    public function enrollmentRules(): array
    {
        return [];
    }

    /**
     * Confirming means "I've saved these". New codes replace the old ones.
     */
    public function confirmEnrollment(Authenticatable&Model $user, Enrollment $enrollment, Request $request): ?Authenticator
    {
        $this->ensureSomethingToRecover($user);

        return $this->make($enrollment->state('secret'));
    }

    /**
     * Codes are a fallback, so the first set needs a real second factor to
     * back up, or every login would spend one. A live set can be replaced.
     * Checked here, when a set would be stored, rather than at begin, which
     * every factor allows.
     *
     * @throws ValidationException
     */
    protected function ensureSomethingToRecover(Authenticatable&Model $user): void
    {
        $keyring = Keyring::for($user);

        if (! $keyring->hasFactorToRecover() && ! $keyring->hasRecoveryCodes()) {
            throw ValidationException::withMessages(['authenticator' => __('keyring::keyring.recovery_needs_second_factor')]);
        }
    }

    /**
     * A recovery codes authenticator for the given secret.
     */
    public function make(#[\SensitiveParameter] string $secret): Authenticator
    {
        return $this->makeAuthenticator(['name' => __('Recovery codes'), 'secret' => $secret]);
    }

    /**
     * Make a fresh set of codes. Returns the plain codes to show the user once,
     * and the secret to store.
     *
     * @return array{codes: list<string>, secret: string}
     */
    public function generate(): array
    {
        // 128 random bits each, as OWASP ASVS 5.0.0 (11.5.1) asks of anything
        // that mustn't be guessed: 26 lowercase base32 characters, in groups of four with
        // the last two on their own, xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xx.
        $codes = array_map(
            fn () => implode('-', str_split(Str::lower(Base32::encodeUnpadded(random_bytes(16))), 4)),
            range(1, $this->count),
        );

        return ['codes' => $codes, 'secret' => $this->secretFor($codes)];
    }

    /**
     * The value to store for a set of plain codes.
     *
     * @param  list<string>  $codes
     *
     * @throws InvalidArgumentException when a code isn't in a form that may be kept as a keyed hash
     */
    public function secretFor(#[\SensitiveParameter] array $codes): string
    {
        return json_encode(array_map($this->hash(...), $codes), JSON_THROW_ON_ERROR);
    }

    /**
     * Whether a code is in a form Keyring stores and accepts.
     */
    public function accepts(#[\SensitiveParameter] string $code): bool
    {
        return $this->canonical($code) !== null;
    }

    /**
     * @return list<string>
     */
    protected function hashes(Authenticator $authenticator): array
    {
        return json_decode($authenticator->secret ?? '[]', true) ?: [];
    }

    protected function hash(#[\SensitiveParameter] string $code): string
    {
        return KeyedHash::make(KeyedHash::RECOVERY_CODES, $this->canonical($code) ?? throw new InvalidArgumentException(
            'Keyring only stores recovery codes with 112 random bits or more: its own (26 base32 characters) or Fortify\'s (20 letters and digits). '
            .'A shorter code is too easy to guess to be kept as a keyed hash (OWASP ASVS 5.0.0, 6.5.2).',
        ));
    }

    /**
     * The code as it's hashed, without the spaces and dashes it's shown or
     * typed with, or null when it's in neither form Keyring keeps. Its own
     * codes read the same in either case. An imported one is left as typed:
     * told apart by case it has 119 bits, lowercased about 102.
     */
    protected function canonical(#[\SensitiveParameter] string $code): ?string
    {
        $code = $this->normalizeCode($code);

        return match (true) {
            preg_match('/^[a-z2-7]{26}$/i', $code) === 1 => Str::lower($code),
            preg_match('/^[a-z0-9]{20}$/i', $code) === 1 => $code,
            default => null,
        };
    }
}
