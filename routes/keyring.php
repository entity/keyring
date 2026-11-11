<?php

use Illuminate\Support\Facades\Route;
use Keyring\Features;
use Keyring\Http\Controllers\AuthenticatedSessionController;
use Keyring\Http\Controllers\AuthenticatorController;
use Keyring\Http\Controllers\ChallengeController;
use Keyring\Http\Controllers\DeviceController;
use Keyring\Http\Controllers\EmailChangeController;
use Keyring\Http\Controllers\EmailVerificationController;
use Keyring\Http\Controllers\PasswordController;
use Keyring\Http\Controllers\PasswordResetController;
use Keyring\Http\Controllers\RegisteredUserController;
use Keyring\Http\Controllers\SessionController;

$guard = config('keyring.guard');

// Routes that read and then write Keyring's session state (pending logins,
// code guesses, WebAuthn challenges, and the challenge pages that save them)
// call block() to take the session lock, so parallel requests can't each
// spend the same state or write back a stale copy of it.

// One challenge controller serves signing in and step-up alike.
$challenge = function () {
    Route::get('/{factor?}', [ChallengeController::class, 'show'])->block()->name('challenge');
    Route::post('/{factor}', [ChallengeController::class, 'verify'])->block()->name('verify');
    Route::post('/{factor}/send', [ChallengeController::class, 'send'])->block()->name('send');
};

Route::middleware('guest:'.$guard)->group(function () use ($challenge) {
    if (Features::enabled(Features::registration())) {
        Route::get('/register', [RegisteredUserController::class, 'create'])->name('register');
        Route::post('/register', [RegisteredUserController::class, 'store'])->middleware('throttle:keyring')->name('register.store');
    }

    if (Features::enabled(Features::resetPasswords())) {
        Route::get('/forgot-password', [PasswordResetController::class, 'create'])->name('password.request');
        Route::post('/forgot-password', [PasswordResetController::class, 'store'])->middleware('throttle:keyring')->name('password.email');
        Route::get('/reset-password/{token}', [PasswordResetController::class, 'edit'])->name('password.reset');
        Route::post('/reset-password', [PasswordResetController::class, 'update'])->middleware('throttle:keyring')->name('password.update');
    }

    Route::get('/login', [AuthenticatedSessionController::class, 'create'])->name('login');
    Route::post('/login', [AuthenticatedSessionController::class, 'store'])->block()->name('login.store');

    Route::prefix('/login/challenge')->name('keyring.login.')->group($challenge);

    // Sign in with another primary factor, like a passkey: /login/passkey
    Route::get('/login/{factor}/options', [AuthenticatedSessionController::class, 'options'])
        ->where('factor', '(?!challenge$)[a-z0-9-]+')
        ->middleware('throttle:keyring-login-options')
        ->name('keyring.login.options');
    Route::post('/login/{factor}', [AuthenticatedSessionController::class, 'store'])
        ->where('factor', '(?!challenge$)[a-z0-9-]+')
        ->block()
        ->name('keyring.login.factor');
});

Route::middleware('auth:'.$guard)->group(function () use ($challenge) {
    Route::prefix('/confirm')->name('keyring.confirm.')->group($challenge);

    // Changing how someone signs in needs a recent verification.
    Route::middleware(config('keyring.changes_middleware'))->group(function () {
        if (Features::enabled(Features::manageAuthenticators())) {
            Route::prefix('/user/authenticators')->name('keyring.authenticators.')->group(function () {
                Route::post('/{factor}', [AuthenticatorController::class, 'store'])->block()->name('store');
                Route::post('/{factor}/confirm', [AuthenticatorController::class, 'confirm'])->middleware('throttle:keyring')->block()->name('confirm');
                Route::patch('/{authenticator}', [AuthenticatorController::class, 'update'])->name('update');
                Route::delete('/{authenticator}', [AuthenticatorController::class, 'destroy'])->middleware('throttle:keyring')->name('destroy');
            });
        }

        // Sessions are kept whatever the features, so ending them is always there.
        Route::delete('/user/sessions', [SessionController::class, 'destroyOthers'])->name('keyring.sessions.destroy-others');
        // Only something shaped like a handle gets as far as being looked for
        // or logged. A registry ID isn't.
        Route::delete('/user/sessions/{session}', [SessionController::class, 'destroy'])->where('session', '[0-9a-f]{64}')->name('keyring.sessions.destroy');

        if (Features::enabled(Features::devices())) {
            Route::delete('/user/devices', [DeviceController::class, 'destroyOthers'])->name('keyring.devices.destroy-others');
            Route::delete('/user/devices/{device}', [DeviceController::class, 'destroy'])->name('keyring.devices.destroy');
        }

        if (Features::enabled(Features::updatePasswords())) {
            Route::put('/user/password', [PasswordController::class, 'update'])->middleware('throttle:keyring')->name('user-password.update');
        }

        if (Features::enabled(Features::emailChanges())) {
            Route::post('/user/email', [EmailChangeController::class, 'store'])->middleware('throttle:keyring')->name('keyring.email.store');
        }
    });

    Route::get('/user/sessions', [SessionController::class, 'index'])->name('keyring.sessions.index');

    if (Features::enabled(Features::devices())) {
        Route::get('/user/devices', [DeviceController::class, 'index'])->name('keyring.devices.index');
    }

    if (Features::enabled(Features::emailChanges())) {
        Route::get('/user/email', [EmailChangeController::class, 'show'])->name('keyring.email.show');
        Route::delete('/user/email', [EmailChangeController::class, 'destroy'])->name('keyring.email.destroy');
    }

    if (Features::enabled(Features::emailVerification())) {
        Route::get('/email/verify', [EmailVerificationController::class, 'notice'])->name('verification.notice');
        Route::get('/email/verify/{id}/{hash}', [EmailVerificationController::class, 'verify'])->middleware(['keyring.signed:relative', 'throttle:keyring'])->name('verification.verify');
        Route::post('/email/verification-notification', [EmailVerificationController::class, 'send'])->middleware('throttle:keyring')->name('verification.send');
    }

    Route::post('/logout', [AuthenticatedSessionController::class, 'destroy'])->name('logout');
});

// Emailed links. GET only shows a page with a button and the POST acts, so a
// mail scanner that opens a link changes nothing. keyring.signed is Laravel's
// signed middleware, which also logs the links it refuses.
Route::middleware('throttle:keyring')->group(function () {
    if (Features::enabled(Features::emailChanges())) {
        Route::get('/email-changes/{change}/confirm/{token}', [EmailChangeController::class, 'page'])->name('keyring.email.confirm');
        Route::post('/email-changes/{change}/confirm/{token}', [EmailChangeController::class, 'confirm'])->name('keyring.email.confirm.store');
        Route::get('/email-changes/{change}/revert/{token}', [EmailChangeController::class, 'page'])->name('keyring.email.revert');
        Route::post('/email-changes/{change}/revert/{token}', [EmailChangeController::class, 'revert'])->name('keyring.email.revert.store');
    }

    if (Features::enabled(Features::devices())) {
        Route::middleware('keyring.signed:relative')->group(function () {
            Route::get('/devices/{device}/report', [DeviceController::class, 'page'])->name('keyring.devices.report');
            Route::post('/devices/{device}/report', [DeviceController::class, 'report'])->name('keyring.devices.report.store');
        });
    }
});
