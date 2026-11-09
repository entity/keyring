<?php

namespace Keyring\Support;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Validation\Rules\Password;
use Keyring\Facades\Keyring;

/**
 * Password rules following OWASP: length over complexity, no composition
 * rules, breached passwords blocked, and no silent truncation.
 */
final class PasswordRules
{
    /** The most common passwords long enough to pass the length rules (from SecLists, MIT). */
    private const string COMMON = __DIR__.'/../../resources/passwords/common.txt';

    /** @var array<string, int>|null */
    private static ?array $common = null;

    /**
     * The rules for a new password. Pass a callback to adjust the Password
     * rule Keyring builds, e.g. fn (Password $rule) => $rule->mixedCase(),
     * and $context for words a password mustn't contain at registration,
     * when there's no user yet (their name and email).
     *
     * @param  (Closure(Password): Password)|null  $adjust
     * @param  list<mixed>  $context
     * @return list<mixed>
     */
    public static function for((Authenticatable&Model)|null $user = null, ?Closure $adjust = null, array $context = []): array
    {
        $hasMfa = $user !== null && Keyring::for($user)->hasSecondFactor();

        $rule = Password::min(config($hasMfa ? 'keyring.passwords.min_with_mfa' : 'keyring.passwords.min_without_mfa'))
            ->max(config('keyring.passwords.max'));

        if (config('keyring.passwords.uncompromised') ?? app()->isProduction()) {
            $rule->uncompromised();
        }

        if ($adjust !== null) {
            $rule = $adjust($rule);
        }

        $context = [...$context, config('app.name'), $user?->getAttribute('name'), $user?->getAttribute(Keyring::username())];

        return ['required', 'string', 'confirmed', $rule, self::notCommon(), self::withoutContext($context), self::bcryptLimit()];
    }

    /**
     * The breached-password check needs Have I Been Pwned, and lets
     * passwords through when it can't be reached. These are refused anyway
     * (OWASP ASVS: at least the 3,000 most common).
     */
    private static function notCommon(): Closure
    {
        return function (string $attribute, mixed $value, Closure $fail) {
            self::$common ??= array_flip(file(self::COMMON, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []);

            if (is_string($value) && isset(self::$common[Str::lower($value)])) {
                $fail(__('keyring::keyring.password_common'));
            }
        };
    }

    /**
     * Not the app's name, or the user's name or email username (OWASP ASVS).
     * Words shorter than four characters don't count.
     *
     * @param  list<mixed>  $context
     */
    private static function withoutContext(array $context): Closure
    {
        $words = collect($context)
            ->filter(fn (mixed $value) => is_string($value))
            ->flatMap(fn (string $value) => preg_split('/[\s@._+-]+/', Str::lower(Str::before($value, '@'))) ?: [])
            ->filter(fn (string $word) => mb_strlen($word) >= 4)
            ->unique()
            ->values();

        return function (string $attribute, mixed $value, Closure $fail) use ($words) {
            if (is_string($value) && $words->contains(fn (string $word) => str_contains(Str::lower($value), $word))) {
                $fail(__('keyring::keyring.password_context'));
            }
        };
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
        return str_starts_with((string) $hash, '$2') && (strlen($password) > 72 || str_contains($password, "\0")) ? Str::random(32) : $password;
    }

    /**
     * Bcrypt only uses the first 72 bytes. Refuse longer passwords instead of
     * silently ignoring the end of them.
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
