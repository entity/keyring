<?php

use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Support\Facades\Notification;
use Keyring\Facades\Keyring;
use Keyring\Models\Device;
use Keyring\Notifications\SecurityNotice;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    config(['app.url' => 'https://app.example.com']);
    Notification::fake();
    Keyring::notify(['new_device']);
});

it('builds the "this wasn\'t me" link from APP_URL, not the Host header', function () {
    $user = taylor();

    $this->withServerVariables(['HTTP_HOST' => 'evil.test'])
        ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $url = null;
    Notification::assertSentTo($user, SecurityNotice::class, function (SecurityNotice $notice) use (&$url) {
        $url = $notice->actionUrl;

        return true;
    });

    expect($url)->toStartWith('https://app.example.com/devices/');

    // The relative signature still works however the app is reached.
    $this->post(parse_url($url, PHP_URL_PATH).'?'.parse_url($url, PHP_URL_QUERY))->assertRedirect(route('login'));
    expect(Device::sole()->isRevoked())->toBeTrue();
});

it('builds email verification links from APP_URL, not the Host header', function () {
    $user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password']);

    $this->actingAs($user)
        ->withServerVariables(['HTTP_HOST' => 'evil.test'])
        ->post('/email/verification-notification');

    $url = null;
    Notification::assertSentTo($user, VerifyEmail::class, function (VerifyEmail $notification) use ($user, &$url) {
        $url = $notification->toMail($user)->actionUrl;

        return true;
    });

    expect($url)->toStartWith('https://app.example.com/email/verify/');

    $this->get(parse_url($url, PHP_URL_PATH).'?'.parse_url($url, PHP_URL_QUERY))->assertRedirect();
    expect($user->fresh()->hasVerifiedEmail())->toBeTrue();
});
