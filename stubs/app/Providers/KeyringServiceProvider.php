<?php

declare(strict_types=1);

namespace App\Providers;

use App\Actions\Keyring\CreateNewUser;
use App\Actions\Keyring\ResetUserPassword;
use App\Actions\Keyring\UpdateUserPassword;
use App\Actions\Keyring\ValidateEmailChange;
use App\Notifications\Keyring as Notifications;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\ServiceProvider;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Requirement;
use Keyring\Risk\Signals;

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

        // Everyone needs a second factor: until they've set one up, every page
        // sends them to the "enrollment_url" in config/keyring.php.
        $this->app->make(Kernel::class)->appendMiddlewareToGroup('web', 'keyring.enrolled');

        // What makes a sign in or a session look like someone else's. Each
        // signal that fires adds to a score, and Keyring answers the total: a
        // second factor from a user who has one, then a notice, and at the
        // top a refused sign in. The ones that are on can't add up to that
        // for a user who signs in with a password alone. See "Risk".
        Keyring::risk()->signals([
            Signals\SessionFingerprintChanged::class,
            // These two read the security log: Features::securityLog().
            Signals\RepeatedFactorFailures::class,
            Signals\SuccessAfterFailures::class,
            // These two go by an account's devices: Features::devices().
            Signals\NewDevice::class,
            Signals\InactiveAccount::class,
            // Off: with the ones above it could refuse a user who has no
            // second factor to give. It needs Features::emailChanges().
            // Signals\RecentlyChangedRecovery::class,
            // Off: it asks Have I Been Pwned at every sign in, and holds a
            // user whose password it finds until they choose another. Set
            // "password_change_url" in config/keyring.php before turning it on.
            // Signals\BreachedPassword::class,
            // Off: these two need a locator, "devices.locator" in the config.
            // Signals\NewCountry::class,
            // Signals\ImpossibleTravel::class,
        ]);

        // Your code for the account changes, in app/Actions/Keyring. Keyring
        // does the security work around them.
        Keyring::createUsersUsing(CreateNewUser::class);
        Keyring::resetUserPasswordsUsing(ResetUserPassword::class);
        Keyring::updateUserPasswordsUsing(UpdateUserPassword::class);
        Keyring::validateEmailChangesUsing(ValidateEmailChange::class);

        // The emails Keyring sends, in app/Notifications/Keyring. They're
        // yours to restyle or send another way, and a security notice that
        // isn't listed here isn't sent. One that's commented out has nothing
        // to announce until its feature is on. See "Security Log & Emails".
        Keyring::notifications([
            'verification_code' => Notifications\VerificationCode::class,
            'confirm_email_change' => Notifications\ConfirmEmailChange::class,
            'email_change_notice' => Notifications\EmailChangeNotice::class,
            'email_address_in_use' => Notifications\EmailAddressInUse::class,
            'already_registered' => Notifications\AlreadyRegistered::class,
            'password_changed' => Notifications\PasswordChanged::class,
            'authenticator_added' => Notifications\AuthenticatorAdded::class,
            'authenticator_removed' => Notifications\AuthenticatorRemoved::class,
            'recovery_code_used' => Notifications\RecoveryCodeUsed::class,
            'recovery_codes_generated' => Notifications\RecoveryCodesGenerated::class,
            'email_changed' => Notifications\EmailChanged::class,
            'account_locked' => Notifications\AccountLocked::class,
            'new_device' => Notifications\NewDevice::class,
            'second_factor_failed' => Notifications\SecondFactorFailed::class,
            'suspicious_activity' => Notifications\SuspiciousActivity::class,
            'email_change_reverted' => Notifications\EmailChangeReverted::class,
            // 'clone_suspected' => Notifications\CloneSuspected::class,
        ]);
    }
}
