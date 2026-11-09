<?php

namespace App\Providers;

use App\Actions\Keyring\CreateNewUser;
use App\Actions\Keyring\ResetUserPassword;
use App\Actions\Keyring\UpdateUserPassword;
use App\Actions\Keyring\ValidateEmailChange;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Requirement;

class KeyringServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // How your users can sign in. See "Factors" in the docs for more.
        Keyring::factors([
            Password::class,
            Totp::class,
            RecoveryCodes::class,
            WebAuthn::passkeys(),
            WebAuthn::securityKeys(),
            EmailCode::asSecondFactor(),
        ]);

        // What they must prove: a second factor once they've set one up, and
        // a passkey or security key whenever they have one. See "Policies".
        Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade());

        // Your code for the account changes, in app/Actions/Keyring. Keyring
        // does the security work around them.
        Keyring::createUsersUsing(CreateNewUser::class);
        Keyring::resetUserPasswordsUsing(ResetUserPassword::class);
        Keyring::updateUserPasswordsUsing(UpdateUserPassword::class);
        Keyring::validateEmailChangesUsing(ValidateEmailChange::class);

        // The limit on registration, password resets and changes, enrollment
        // and emailed links. Sign in attempts use the "limits" config instead.
        RateLimiter::for('keyring', fn (Request $request) => Limit::perMinute(6)->by(Keyring::guard()->id() ?: $request->ip()));
    }
}
