<?php

namespace App\Providers;

use App\Actions\Keyring\CreateNewUser;
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

        Keyring::createUsersUsing(CreateNewUser::class);

        // Security emails (new sign in, password changed, failed second factor...).
        // Keyring::notify();

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
