<?php

use Illuminate\Support\Facades\Route;
use Keyring\Http\Controllers\AuthenticatedSessionController;
use Keyring\Http\Controllers\AuthenticatorController;
use Keyring\Http\Controllers\ChallengeController;
use Keyring\Http\Controllers\DeviceController;

$guard = config('keyring.guard');

Route::middleware('guest:'.$guard)->group(function () {
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

Route::get('/user/devices', [DeviceController::class, 'index'])->middleware('auth:'.$guard)->name('keyring.devices.index');

Route::get('/devices/{device}/report', [DeviceController::class, 'report'])
    ->middleware(['signed', 'throttle:6,1'])
    ->name('keyring.devices.report');

Route::post('/logout', [AuthenticatedSessionController::class, 'destroy'])
    ->middleware('auth:'.$guard)
    ->name('logout');
