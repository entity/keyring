<?php

use Illuminate\Support\Facades\Route;
use Keyring\Http\Controllers\AuthenticatedSessionController;
use Keyring\Http\Controllers\AuthenticatorController;
use Keyring\Http\Controllers\ChallengeController;
use Keyring\Http\Controllers\DeviceController;
use Keyring\Http\Controllers\EmailChangeController;
use Keyring\Http\Controllers\PasswordController;
use Keyring\Http\Controllers\PasswordResetController;

$guard = config('keyring.guard');

Route::middleware('guest:'.$guard)->group(function () {
    Route::get('/forgot-password', [PasswordResetController::class, 'create'])->name('password.request');
    Route::post('/forgot-password', [PasswordResetController::class, 'store'])->middleware('throttle:6,1')->name('password.email');
    Route::get('/reset-password/{token}', [PasswordResetController::class, 'edit'])->name('password.reset');
    Route::post('/reset-password', [PasswordResetController::class, 'update'])->middleware('throttle:6,1')->name('password.update');

    Route::get('/login', [AuthenticatedSessionController::class, 'create'])->name('login');
    Route::post('/login', [AuthenticatedSessionController::class, 'store'])->name('login.store');

    Route::prefix('/login/challenge')->name('keyring.login.')->group(function () {
        Route::get('/{factor?}', [ChallengeController::class, 'show'])->name('challenge');
        Route::post('/{factor}', [ChallengeController::class, 'verify'])->name('verify');
        Route::post('/{factor}/send', [ChallengeController::class, 'send'])->name('send');
    });

    // Sign in with another primary factor, like a passkey: /login/passkey
    Route::get('/login/{factor}/options', [AuthenticatedSessionController::class, 'options'])
        ->where('factor', '^(?!challenge$)[a-z0-9-]+$')
        ->name('keyring.login.options');
    Route::post('/login/{factor}', [AuthenticatedSessionController::class, 'store'])
        ->where('factor', '^(?!challenge$)[a-z0-9-]+$')
        ->name('keyring.login.factor');
});

Route::middleware('auth:'.$guard)->prefix('/confirm')->name('keyring.confirm.')->group(function () {
    Route::get('/{factor?}', [ChallengeController::class, 'show'])->name('challenge');
    Route::post('/{factor}', [ChallengeController::class, 'verify'])->name('verify');
    Route::post('/{factor}/send', [ChallengeController::class, 'send'])->name('send');
});

Route::middleware(config('keyring.manage_middleware'))->prefix('/user/authenticators')->name('keyring.authenticators.')->group(function () {
    Route::post('/{factor}', [AuthenticatorController::class, 'store'])->name('store');
    Route::post('/{factor}/confirm', [AuthenticatorController::class, 'confirm'])->middleware('throttle:6,1')->name('confirm');
    Route::patch('/{authenticator}', [AuthenticatorController::class, 'update'])->name('update');
    Route::delete('/{authenticator}', [AuthenticatorController::class, 'destroy'])->name('destroy');
});

Route::middleware(config('keyring.manage_middleware'))->prefix('/user/devices')->name('keyring.devices.')->group(function () {
    Route::delete('/', [DeviceController::class, 'destroyOthers'])->name('destroy-others');
    Route::delete('/{device}', [DeviceController::class, 'destroy'])->name('destroy');
});

Route::middleware(config('keyring.manage_middleware'))->group(function () {
    Route::put('/user/password', [PasswordController::class, 'update'])->name('user-password.update');
    Route::post('/user/email', [EmailChangeController::class, 'store'])->middleware('throttle:6,1')->name('keyring.email.store');
});

Route::middleware('auth:'.$guard)->group(function () {
    Route::get('/user/email', [EmailChangeController::class, 'show'])->name('keyring.email.show');
    Route::delete('/user/email', [EmailChangeController::class, 'destroy'])->name('keyring.email.destroy');
});

Route::middleware('throttle:12,1')->group(function () {
    Route::get('/email-changes/{change}/confirm/{token}', [EmailChangeController::class, 'confirm'])->name('keyring.email.confirm');
    Route::get('/email-changes/{change}/revert/{token}', [EmailChangeController::class, 'revert'])->name('keyring.email.revert');
});

Route::get('/user/devices', [DeviceController::class, 'index'])->middleware('auth:'.$guard)->name('keyring.devices.index');

Route::get('/devices/{device}/report', [DeviceController::class, 'report'])
    ->middleware(['signed', 'throttle:6,1'])
    ->name('keyring.devices.report');

Route::post('/logout', [AuthenticatedSessionController::class, 'destroy'])
    ->middleware('auth:'.$guard)
    ->name('logout');
