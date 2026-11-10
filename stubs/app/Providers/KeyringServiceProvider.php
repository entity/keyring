<?php

namespace App\Providers;

use App\Actions\Keyring\CreateNewUser;
use App\Actions\Keyring\ResetUserPassword;
use App\Actions\Keyring\UpdateUserPassword;
use App\Actions\Keyring\ValidateEmailChange;
use App\Notifications\Keyring as Notifications;
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

        // The emails Keyring sends, in app/Notifications/Keyring. They're
        // yours to restyle or send another way, and a security notice that
        // isn't listed here isn't sent. See "Security Log & Emails".
        Keyring::notifications([
            'verification_code' => Notifications\VerificationCode::class,
            'confirm_email_change' => Notifications\ConfirmEmailChange::class,
            'email_change_notice' => Notifications\EmailChangeNotice::class,
            'email_address_in_use' => Notifications\EmailAddressInUse::class,
            'password_changed' => Notifications\PasswordChanged::class,
            'authenticator_added' => Notifications\AuthenticatorAdded::class,
            'authenticator_removed' => Notifications\AuthenticatorRemoved::class,
            'recovery_code_used' => Notifications\RecoveryCodeUsed::class,
            // 'new_device' => Notifications\NewDevice::class,
            // 'second_factor_failed' => Notifications\SecondFactorFailed::class,
            // 'suspicious_activity' => Notifications\SuspiciousActivity::class,
            // 'clone_suspected' => Notifications\CloneSuspected::class,
            // 'email_changed' => Notifications\EmailChanged::class,
            // 'email_change_reverted' => Notifications\EmailChangeReverted::class,
        ]);

        // The limit on registration, password resets and changes, enrollment
        // and emailed links. Sign in attempts use the "limits" config instead.
        RateLimiter::for('keyring', fn (Request $request) => Limit::perMinute(6)->by(Keyring::guard()->id() ?: $request->ip()));
    }
}
