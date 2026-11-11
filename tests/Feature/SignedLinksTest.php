<?php

declare(strict_types=1);

use App\Notifications\Keyring\NewDevice;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Support\Facades\Notification;
use Keyring\Models\Device;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    config(['app.url' => 'https://app.example.com']);
    Notification::fake();
    sendNotifications(['new_device']);
});

it('builds the "this wasn\'t me" link from APP_URL, not the Host header', function () {
    $user = taylor();

    $this->withServerVariables(['HTTP_HOST' => 'evil.test'])
        ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $url = null;
    Notification::assertSentTo($user, NewDevice::class, function (NewDevice $notice) use (&$url) {
        $url = $notice->url;

        return true;
    });

    expect($url)->toStartWith('https://app.example.com/devices/');

    // The relative signature still works however the app is reached.
    postSignedLink($url)->assertRedirect(route('login'));
    expect(Device::sole()->isRevoked())->toBeTrue();
});

it('builds email verification links from APP_URL, not the Host header', function () {
    // A signed-in user asks for the link, which takes registration that signs new users in.
    revealTakenAddresses();
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

    postSignedLink($url)->assertRedirect();
    expect($user->fresh()->hasVerifiedEmail())->toBeTrue();
});

// Behind a proxy the app trusts, X-Forwarded-Prefix becomes part of every URL
// Laravel builds for the request. Whoever sends the request can set it when
// the proxy passes it on, so it stays out of emailed links.
describe('with a forwarded prefix the app trusts', function () {
    beforeEach(function () {
        TrustProxies::at('*');
    });

    afterEach(function () {
        TrustProxies::flushState();
    });

    it('leaves it out of what a verification link signs', function () {
        revealTakenAddresses();
        $other = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password']);
        $user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password']);

        $this->actingAs($user)
            ->withHeader('X-Forwarded-Prefix', "/email/verify/{$other->id}/".sha1('abigail@example.com').'?x=')
            ->post('/email/verification-notification');

        $url = null;
        Notification::assertSentTo($user, VerifyEmail::class, function (VerifyEmail $notification) use ($user, &$url) {
            $url = $notification->toMail($user)->actionUrl;

            return true;
        });

        expect($url)->toStartWith("https://app.example.com/email/verify/{$user->id}/".sha1('taylor@example.com').'?expires=');
    });

    it('leaves it out of a reset link', function () {
        $user = taylor();

        $this->withHeader('X-Forwarded-Prefix', '/out?to=//evil.test')
            ->post('/forgot-password', ['email' => 'taylor@example.com']);

        Notification::assertSentTo($user, ResetPassword::class, fn (ResetPassword $notification) => str_starts_with($notification->toMail($user)->actionUrl, 'https://app.example.com/reset-password/'.$notification->token.'?'));
    });

    it('leaves it out of the "this wasn\'t me" link', function () {
        $user = taylor();

        $this->withHeader('X-Forwarded-Prefix', '/devices/01HZZZZZZZZZZZZZZZZZZZZZZZ/report?x=')
            ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

        Notification::assertSentTo($user, NewDevice::class, fn (NewDevice $notice) => str_starts_with($notice->url, 'https://app.example.com/devices/'.Device::sole()->id.'/report?expires='));
    });

    it('still accepts a signed link when the proxy adds an ordinary prefix', function () {
        $user = taylor();
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

        $url = null;
        Notification::assertSentTo($user, NewDevice::class, function (NewDevice $notice) use (&$url) {
            $url = $notice->url;

            return true;
        });

        $this->withHeader('X-Forwarded-Prefix', '/app');

        postSignedLink($url)->assertRedirect();

        expect(Device::sole()->isRevoked())->toBeTrue();
    });
});
