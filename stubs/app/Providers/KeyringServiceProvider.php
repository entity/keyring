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
        // Every way your users can sign in.
        Keyring::factors([
            Password::class,
            WebAuthn::passkeys(),
            WebAuthn::securityKeys(),
            Totp::class,
            EmailCode::class,
            RecoveryCodes::class,
        ]);

        // What they must prove. Two factors once they've set one up, and a
        // passkey or security key whenever they have one.
        Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade());

        // Or decide per user and attempt:
        // Keyring::require(fn (User $user, Attempt $attempt) => match (true) {
        //     $user->is_admin => Requirement::aal2()->phishingResistant(),
        //     $attempt->device()?->isTrusted() === true => Requirement::aal1(),
        //     default => Requirement::aal2()->ifEnrolled(),
        // });

        // Your code for the account changes: validation and saving live in
        // app/Actions/Keyring. Keyring does the security work around them.
        Keyring::createUsersUsing(CreateNewUser::class);
        Keyring::resetUserPasswordsUsing(ResetUserPassword::class);
        Keyring::updateUserPasswordsUsing(UpdateUserPassword::class);
        Keyring::validateEmailChangesUsing(ValidateEmailChange::class);

        // Find users your own way (by email or username, skipping banned
        // accounts...), or keep new users signed out until they're approved:
        // Keyring::findUsersUsing(fn (Request $request) => User::firstWhere('email', $request->email));
        // Keyring::signInAfterRegistering(false);

        // The limit on registration, password resets and changes, enrollment
        // and emailed links. Sign in attempts use the "limits" config instead.
        RateLimiter::for('keyring', fn (Request $request) => Limit::perMinute(6)->by(Keyring::guard()->id() ?: $request->ip()));

        // Keyring renders your Inertia pages auth/login, auth/challenge... (or
        // Blade views auth.login...). Point any of them elsewhere:
        // Keyring::page('confirm', 'auth/challenge');

        // Security notices (new sign in, password changed, failed second
        // factor...), by email unless you extend SecurityNotice for Slack & co.
        // Keyring::notify();
        // Keyring::securityNoticesUsing(\App\Notifications\SecurityNotice::class);

        // Risk signals and what to do about them.
        // Keyring::risk([NewDevice::class, NewCountry::class, ImpossibleTravel::class])
        //     ->respond(fn (Risk $risk) => match ($risk->level) {
        //         Level::Low => Action::allow(),
        //         Level::Medium => Action::stepUp(),
        //         Level::High => Action::stepUp()->notify(),
        //         Level::Critical => Action::deny()->revokeAllSessions()->notify(),
        //     });
    }
}
