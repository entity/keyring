<?php

use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Notification;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\Totp;
use Keyring\Models\Authenticator;
use Keyring\Notifications\VerificationCode;
use Keyring\Tests\Fixtures\SmsCode;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    SmsCode::$sent = [];
    Keyring::factors([Password::class, Totp::class, EmailCode::class, SmsCode::class]);

    $this->user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password', 'email_verified_at' => now()]);
});

it('keeps what a custom code factor collects at enrollment', function () {
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

    $this->postJson(route('keyring.authenticators.store', 'sms'), ['phone' => '+447700900001'])->assertOk();
    $this->postJson(route('keyring.authenticators.confirm', 'sms'), ['code' => SmsCode::$sent['+447700900001'], 'name' => 'Work phone'])
        ->assertOk();

    $phone = $this->user->keyring->refresh()->of('sms')->sole();
    expect($phone->secret)->toBe('+447700900001')
        ->and($phone->name)->toBe('Work phone');
});

it('only accepts a code for the authenticator it was sent to', function () {
    $first = Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'sms', 'name' => 'Phone A', 'secret' => '+447700900001', 'is_default' => true]);
    $second = Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'sms', 'name' => 'Phone B', 'secret' => '+447700900002']);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.send', 'sms'), ['authenticator' => $first->id]);

    $this->post(route('keyring.login.verify', 'sms'), ['authenticator' => $second->id, 'code' => SmsCode::$sent['+447700900001']])
        ->assertSessionHasErrors('code');
    $this->assertGuest();
});

it('keeps a single email code method, since every copy would go to the same address', function () {
    Notification::fake();
    Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'email-code', 'name' => 'Email']);

    $this->actingAs($this->user)->withAssurance(Assurance::AAL2)->postJson(route('keyring.authenticators.store', 'email-code'));

    Notification::assertSentTo($this->user, VerificationCode::class, function (VerificationCode $notification) {
        $this->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => $notification->code])->assertOk();

        return true;
    });

    expect($this->user->keyring->refresh()->of('email-code'))->toHaveCount(1);
});

it('keeps enrollments small in the session', function () {
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
        ->postJson(route('keyring.authenticators.store', 'totp'))
        ->assertJsonStructure(['enrollment' => ['qr']]);

    expect(json_decode(Crypt::decryptString(session('keyring.enrollment.totp')), true))->not->toHaveKey('props');
});
