<?php

declare(strict_types=1);

namespace Keyring\Support;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Validation\Rules\Password;
use Keyring\Facades\Keyring;
use LogicException;
use Normalizer;

/**
 * Password rules: length over complexity, no composition rules, breached
 * passwords blocked, and no silent truncation.
 */
final class PasswordRules
{
    /** The shortest password any setting may allow (OWASP ASVS 5.0.0 6.2.1, NIST SP 800-63B-4 Sec. 3.1.1.2). */
    public const int SHORTEST = 8;

    /**
     * The most common passwords long enough to pass the length rules: the
     * top 10,000 of 8 characters or more and the top 3,000 of 15 or more,
     * trimmed and lowercased. The README beside it has the source (SecLists,
     * MIT) and how it's built.
     */
    private const string COMMON = __DIR__.'/../../resources/passwords/common.txt';

    /**
     * Characters people swap for the letters they look like, so k3yr1ng
     * reads as keyring. 1, i and l all read as one letter.
     */
    private const array LOOKALIKES = ['0' => 'o', '1' => 'i', 'l' => 'i', '3' => 'e', '4' => 'a', '5' => 's', '7' => 't', '@' => 'a', '$' => 's'];

    /**
     * Where anyone can have an address, by the first label of the domain
     * (gmail.com, yahoo.co.uk). It says nothing about the user, unlike the
     * megacorp of megacorp.example.
     */
    private const array PUBLIC_MAIL = [
        'gmail', 'googlemail', 'outlook', 'hotmail', 'live', 'yahoo', 'ymail', 'icloud', 'proton', 'protonmail',
        'fastmail', 'tutanota', 'yandex', 'zoho', 'mail', 'email',
    ];

    /** Have I Been Pwned's range search: every breached hash that starts with five characters. */
    private const string BREACHES = 'https://api.pwnedpasswords.com/range/';

    /** @var array<string, int>|null */
    private static ?array $common = null;

    /**
     * The rules for a new password. Pass a callback to adjust the Password
     * rule Keyring builds, e.g. fn (Password $rule) => $rule->rules(['min:20']),
     * and $context for words a password mustn't contain at registration,
     * when there's no user yet (their name and email). Words to do with the
     * app itself go in the passwords.context option.
     *
     * @param  (Closure(Password): Password)|null  $adjust
     * @param  list<mixed>  $context
     * @return list<mixed>
     */
    public static function for((Authenticatable&Model)|null $user = null, ?Closure $adjust = null, array $context = []): array
    {
        $min = self::min($user !== null && Keyring::for($user)->hasSecondFactor());

        $rule = Password::min($min)->max(config('keyring.passwords.max'));

        $breachCheck = config('keyring.passwords.uncompromised') ?? app()->isProduction();
        $strict = $breachCheck && config('keyring.passwords.refuse_unchecked');

        // Laravel's check, unless Keyring is to do its own, stricter one.
        if ($breachCheck && ! $strict) {
            $rule->uncompromised();
        }

        if ($adjust !== null) {
            $rule = $adjust($rule);
        }

        $site = [config('app.name'), ...Arr::wrap(config('keyring.passwords.context'))];
        $personal = [...$context, $user?->getAttribute('name'), $user?->getAttribute(Keyring::username()), $user?->getAttribute(Keyring::email())];

        return [
            'required', 'string', 'confirmed', $rule,
            self::notCommon(), self::withoutContext($site, $personal), self::bcryptLimit(),
            ...$strict ? [self::notBreached($min)] : [],
        ];
    }

    /**
     * The fewest characters a new password needs, with a second factor beside
     * it or on its own. A setting under eight is refused, not raised quietly:
     * an app that asked for four should find out it can't have them.
     *
     * @throws LogicException
     */
    public static function min(bool $withMfa = false): int
    {
        $option = 'keyring.passwords.'.($withMfa ? 'min_with_mfa' : 'min_without_mfa');
        $min = config($option);

        if (! is_numeric($min) || $min < self::SHORTEST) {
            throw new LogicException(sprintf(
                'Keyring\'s [%s] option is %s. A password needs at least %d characters, so set it to %d or more.',
                $option, json_encode($min), self::SHORTEST, self::SHORTEST,
            ));
        }

        return (int) $min;
    }

    /**
     * The breached-password check needs Have I Been Pwned, and lets
     * passwords through when it can't be reached. The most common ones are
     * refused anyway, whatever their case and with or without spaces around
     * them. The list is read once, into an array keyed by password.
     */
    private static function notCommon(): Closure
    {
        return function (string $attribute, mixed $value, Closure $fail) {
            self::$common ??= array_flip(file(self::COMMON, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []);

            if (is_string($value) && isset(self::$common[Str::lower(trim($value))])) {
                $fail(__('keyring::keyring.password_common'));
            }
        };
    }

    /**
     * Laravel's breach check lets a password through when Have I Been Pwned
     * can't be reached: it reports the failure and answers "not breached".
     * With passwords.refuse_unchecked on, Keyring asks itself, the same way
     * (only the first five characters of the password's SHA-1 are sent), and
     * refuses a password it got no answer about. It only ever asks that one
     * host: it follows no redirect. One too short to be taken anyway isn't
     * sent.
     */
    private static function notBreached(int $min): Closure
    {
        return function (string $attribute, mixed $value, Closure $fail) use ($min) {
            if (! is_string($value) || mb_strlen($value) < $min) {
                return;
            }

            $hash = Str::upper(sha1($value));

            // One host and no other: a redirect isn't followed, and what
            // comes back in its place is no answer.
            $range = rescue(fn () => Http::withHeaders(['Add-Padding' => 'true'])->timeout(10)->withoutRedirecting()->get(self::BREACHES.substr($hash, 0, 5))->throw()->body());

            // A range that was read always lists hashes, so anything else is no answer.
            if (! is_string($range) || preg_match('/^[0-9A-F]{35}:\d/mi', $range) !== 1) {
                $fail(__('keyring::keyring.password_unchecked'));

                return;
            }

            // The padding added so an answer's size gives nothing away counts zero.
            if (preg_match('/^'.substr($hash, 5).':0*[1-9]/mi', $range) === 1) {
                $fail('validation.password.uncompromised')->translate();
            }
        };
    }

    /**
     * Not made up of what the app is called or a word it listed, the user's
     * name, their email username or the organisation their address is at,
     * with or without digits and punctuation around them. Characters that
     * stand in for letters count as those letters.
     *
     * The password is compared whole, as NIST SP 800-63B-4 asks (Sec. 3.1.1.2): a passphrase
     * that happens to have a name in it is as hard to guess as one without,
     * and refusing it would be a composition rule by another name. "Taylor
     * rides a blue bicycle" passes, and "taylor.otwell.2026" doesn't.
     *
     * Words under four characters turn up by chance too often to count,
     * except a whole name of the app's, which counts from three ("IBM").
     * A name of several words also counts run together ("My App" as myapp).
     *
     * @param  array<array-key, mixed>  $site  the app's name, and the words it listed, however they're keyed
     * @param  array<array-key, mixed>  $personal  the user's names and addresses
     */
    private static function withoutContext(array $site, array $personal): Closure
    {
        $names = collect($site)->filter(fn (mixed $name) => is_string($name))->map(fn (string $name) => self::words($name));

        $words = collect($personal)
            ->filter(fn (mixed $value) => is_string($value))
            ->flatMap(fn (string $value) => self::personal($value))
            ->merge($names->flatten())
            ->filter(fn (string $word) => mb_strlen($word) >= 4)
            ->merge($names->map(fn (array $name) => implode('', $name))->filter(fn (string $name) => mb_strlen($name) >= 3))
            ->map(fn (string $word) => self::letters($word))
            ->filter()
            ->unique()
            ->values()
            ->all();

        return function (string $attribute, mixed $value, Closure $fail) use ($words) {
            if (! is_string($value)) {
                return;
            }

            // Read twice: with digits and punctuation as padding
            // ("keyring2026" is the word and a year), and with them as the
            // letters they look like ("k3yr1ng" is the word).
            $readings = array_filter([self::plain(self::letters($value)), self::letters(self::plain($value))]);

            if (array_any($readings, fn (string $letters) => self::madeOf($letters, $words))) {
                $fail(__('keyring::keyring.password_context'));
            }
        };
    }

    /**
     * Whether a run of letters is nothing but the given words, one after
     * another, in any order and any number of times.
     *
     * @param  list<string>  $words
     */
    private static function madeOf(string $letters, array $words): bool
    {
        $reached = [0 => true];

        for ($at = 0, $length = strlen($letters); $at < $length; $at++) {
            if (! isset($reached[$at])) {
                continue;
            }

            foreach ($words as $word) {
                if (substr_compare($letters, $word, $at, strlen($word)) === 0) {
                    $reached[$at + strlen($word)] = true;
                }
            }
        }

        return isset($reached[strlen($letters)]);
    }

    /**
     * Only the letters of a value: digits, spaces and punctuation are what
     * people put around a word to make it look like more.
     */
    private static function letters(string $value): string
    {
        return preg_replace('/\P{L}+/u', '', $value) ?? '';
    }

    /**
     * The words in something about the user. Of an address, that's what
     * comes before the @ and the first label of its domain, where the
     * organisation's name usually is, unless anyone can have an address there.
     *
     * @return list<string>
     */
    private static function personal(string $value): array
    {
        if (! str_contains($value, '@')) {
            return self::words($value);
        }

        $organisation = Str::before(Str::afterLast($value, '@'), '.');

        return [
            ...self::words(Str::beforeLast($value, '@')),
            ...in_array(Str::lower($organisation), self::PUBLIC_MAIL, true) ? [] : self::words($organisation),
        ];
    }

    /**
     * The runs of letters and digits in a value, as plain() reads them.
     *
     * @return list<string>
     */
    private static function words(string $value): array
    {
        return preg_split('/[^\p{L}\p{N}]+/u', self::plain($value), flags: PREG_SPLIT_NO_EMPTY) ?: [];
    }

    /**
     * Lowercased, with look-alike characters read as their letters. Used on
     * both sides of a comparison, so it only ever makes more things match.
     */
    private static function plain(string $value): string
    {
        return strtr(Str::lower($value), self::LOOKALIKES);
    }

    /**
     * A password as Keyring hashes and checks it: in Unicode's NFC form, as
     * NIST SP 800-63B-4 recommends (Sec. 3.1.1.2). The same "é" is one code point from one keyboard
     * and two from another, and without this the two wouldn't match. Bytes
     * that aren't UTF-8 have no form to put them in and stay as they are.
     */
    public static function normalize(#[\SensitiveParameter] string $password): string
    {
        return Normalizer::normalize($password, Normalizer::FORM_C) ?: $password;
    }

    /**
     * Request input with the passwords in it normalized, for an action that
     * validates and saves one: the rules then measure what will be hashed.
     *
     * @param  array<string, mixed>  $input
     * @return array<string, mixed>
     */
    public static function normalizeInput(#[\SensitiveParameter] array $input): array
    {
        foreach (['password', 'password_confirmation', 'current_password'] as $key) {
            if (is_string($input[$key] ?? null)) {
                $input[$key] = self::normalize($input[$key]);
            }
        }

        return $input;
    }

    /**
     * What to check against a stored hash. Bcrypt only uses the first 72
     * bytes and stops at a NUL byte, so an input like that would pass on the
     * start of it alone. No bcrypt password can hold either. It's swapped for a
     * random value: a wrong password in every way (same error, same time
     * hashing, same throttling), and the input never reaches the hasher.
     * This goes by the hash, not the default driver: bcrypt hashes outlive a
     * move to argon2, which takes any length. Bcrypt hashes from other systems
     * ($2a$, $2b$) truncate too and password_get_info() doesn't know them.
     */
    public static function forVerifying(#[\SensitiveParameter] string $password, ?string $hash): string
    {
        $password = self::normalize($password);

        return str_starts_with((string) $hash, '$2') && (strlen($password) > 72 || str_contains($password, "\0")) ? Str::random(32) : $password;
    }

    /**
     * Bcrypt only uses the first 72 bytes. Refuse longer passwords instead of
     * silently ignoring the end of them. That's bytes, not characters, so
     * under bcrypt passwords.max is never reached and 64 characters of
     * accented or non-Latin text are too many. Argon2 has no such limit.
     */
    private static function bcryptLimit(): Closure
    {
        return function (string $attribute, mixed $value, Closure $fail) {
            if (Hash::getDefaultDriver() === 'bcrypt' && is_string($value) && strlen($value) > 72) {
                $fail(__('keyring::keyring.password_too_long'));
            }
        };
    }
}
