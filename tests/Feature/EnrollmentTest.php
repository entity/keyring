<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\WebAuthn;
use Keyring\Models\Authenticator;

beforeEach(function () {
    Route::middleware(['web', 'keyring.enrolled'])->get('/dashboard', fn () => 'dashboard');
    Route::middleware(['web', 'keyring.enrolled'])->get('/settings/security', fn () => 'security');
    Route::middleware(['web', 'keyring.enrolled:aal3'])->get('/vault', fn () => 'vault');

    config(['keyring.enrollment_url' => '/settings/security']);

    $this->user = taylor();
});

it('sends users without a second factor to the enrollment page', function () {
    $this->actingAs($this->user)->get('/dashboard')
        ->assertRedirect('/settings/security')
        ->assertSessionHas('status', 'enroll-first');

    $this->get('/settings/security')->assertOk()->assertSee('security');
});

it('tells json requests where to go', function () {
    $this->actingAs($this->user)->getJson('/dashboard')
        ->assertForbidden()
        ->assertJson(['status' => 'enroll-first', 'redirect' => '/settings/security']);
});

it('answers 403 without an enrollment page', function () {
    config(['keyring.enrollment_url' => null]);

    $this->actingAs($this->user)->get('/dashboard')->assertForbidden();
});

it('doesn\'t count recovery codes or email codes', function () {
    Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();
    Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'email-code', 'name' => 'Email']);

    $this->actingAs($this->user)->get('/dashboard')->assertRedirect('/settings/security');
});

it('lets users with a second factor through', function () {
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->actingAs($this->user)->get('/dashboard')->assertOk();
});

it('asks for an attested key that stays on its device at aal3', function () {
    Keyring::factors([Password::class, WebAuthn::passkeys()->requireAttestation()]);

    Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();
    $this->actingAs($this->user)->get('/vault')->assertRedirect('/settings/security');

    // Staying on its device is only the key's word until its maker vouches.
    Authenticator::factory()->passkey(synced: false)->for($this->user, 'authenticatable')->create();
    $this->actingAs($this->user->fresh())->get('/vault')->assertRedirect('/settings/security');

    Authenticator::factory()->passkey(synced: false)->attested('2fc0579f-8113-47ea-b116-bb5a8db9202a')->for($this->user, 'authenticatable')->create();
    $this->actingAs($this->user->fresh())->get('/vault')->assertOk();
});

it('asks for a key that stays on its device, attested or not, when the route says device-bound', function () {
    Route::middleware(['web', 'keyring.enrolled:aal2,device-bound'])->get('/keys-only', fn () => 'keys only');

    Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();
    $this->actingAs($this->user)->get('/keys-only')->assertRedirect('/settings/security');

    Authenticator::factory()->passkey(synced: false)->for($this->user, 'authenticatable')->create();
    $this->actingAs($this->user->fresh())->get('/keys-only')->assertOk();
});

it('leaves guests to auth, so it can sit in the web group', function () {
    $this->get('/dashboard')->assertOk();
});

it('lets users reach the routes they need to enroll and sign out', function () {
    $this->app['router']->pushMiddlewareToGroup('web', 'keyring.enrolled');
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk();
    $this->post(route('logout'))->assertRedirect();
});
