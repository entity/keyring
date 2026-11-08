<?php

use Illuminate\Support\Facades\Route;
use Keyring\Http\Controllers\AuthenticatedSessionController;
use Keyring\Http\Controllers\ChallengeController;

$guard = config('keyring.guard');

Route::middleware('guest:'.$guard)->group(function () {
    Route::get('/login', [AuthenticatedSessionController::class, 'create'])->name('login');
    Route::post('/login', [AuthenticatedSessionController::class, 'store'])->name('login.store');

    Route::prefix('/login/challenge')->name('keyring.login.')->group(function () {
        Route::get('/{factor?}', [ChallengeController::class, 'show'])->name('challenge');
        Route::post('/{factor}', [ChallengeController::class, 'verify'])->name('verify');
    });
});

Route::middleware('auth:'.$guard)->prefix('/confirm')->name('keyring.confirm.')->group(function () {
    Route::get('/{factor?}', [ChallengeController::class, 'show'])->name('challenge');
    Route::post('/{factor}', [ChallengeController::class, 'verify'])->name('verify');
});

Route::post('/logout', [AuthenticatedSessionController::class, 'destroy'])
    ->middleware('auth:'.$guard)
    ->name('logout');
