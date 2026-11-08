<?php

namespace Keyring\Support;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules\Password;
use Keyring\Enums\Category;
use Keyring\Facades\Keyring;
use Keyring\Login\Requirement;

/**
 * Password rules following OWASP: length over complexity, no composition
 * rules, breached passwords blocked, and no silent truncation.
 */
final class PasswordRules
{
    /**
     * @return list<mixed>
     */
    public static function for((Authenticatable&Model)|null $user = null): array
    {
        $hasMfa = $user !== null && Keyring::for($user)->canMeet(Requirement::aal2()->including(Category::Possession));

        $rule = Password::min(config($hasMfa ? 'keyring.passwords.min_with_mfa' : 'keyring.passwords.min_without_mfa'))
            ->max(config('keyring.passwords.max'));

        if (config('keyring.passwords.uncompromised')) {
            $rule->uncompromised();
        }

        // The app's adjustments, from Keyring::passwordRulesUsing().
        $rule = Keyring::adjustPasswordRule($rule, $user);

        return ['required', 'string', 'confirmed', $rule, self::bcryptLimit()];
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
