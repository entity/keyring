<?php

use App\Notifications\Keyring\VerificationCode;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Notification;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\Totp;
use Keyring\Models\Authenticator;
use Keyring\Tests\Fixtures\SmsCode;

class FiveDigitSmsCode extends SmsCode
{
    #[Override]
    protected int $length = 5;
}

class QuarterHourSmsCode extends SmsCode
{
    #[Override]
    protected int $ttl = 900;
}

beforeEach(function () {
    SmsCode::$sent = [];
    Keyring::factors([Password::class, Totp::class, EmailCode::asSecondFactor(), SmsCode::class]);

    $this->user = taylor();
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

    // The code sent to the first phone still works there.
    $this->post(route('keyring.login.verify', 'sms'), ['authenticator' => $first->id, 'code' => SmsCode::$sent['+447700900001']])
        ->assertRedirect('/dashboard');
});

it('counts wrong guesses across every authenticator of a code factor', function () {
    config(['keyring.limits.per_account' => 100]);
    $first = Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'sms', 'name' => 'Phone A', 'secret' => '+447700900001', 'is_default' => true]);
    $second = Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'sms', 'name' => 'Phone B', 'secret' => '+447700900002']);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.send', 'sms'), ['authenticator' => $first->id]);

    foreach (range(1, 4) as $guess) {
        $this->post(route('keyring.login.verify', 'sms'), ['authenticator' => $first->id, 'code' => '00000000']);
    }

    $this->post(route('keyring.login.send', 'sms'), ['authenticator' => $second->id]);
    $this->post(route('keyring.login.verify', 'sms'), ['authenticator' => $second->id, 'code' => '00000000']);

    $this->post(route('keyring.login.verify', 'sms'), ['authenticator' => $second->id, 'code' => SmsCode::$sent['+447700900002']])
        ->assertSessionHasErrors(['code' => __('keyring::keyring.too_many_codes')]);
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

it('refuses a custom code factor whose codes are too short or last too long, when it is registered', function (string $factor, string $message) {
    Keyring::factors([Password::class, $factor]);

    expect(fn () => Keyring::registered())->toThrow(LogicException::class, $message);
})->with([
    'five digits' => [FiveDigitSmsCode::class, 'The [sms] factor sends 5 digit codes. Keyring refuses codes shorter than 6 digits'],
    'fifteen minutes' => [QuarterHourSmsCode::class, 'The [sms] factor keeps its codes for 900 seconds. Keyring refuses a code that lasts longer than 600 seconds'],
]);

it('refuses one added with extend the same way', function () {
    Keyring::extend('sms', fn () => new FiveDigitSmsCode);

    expect(fn () => Keyring::factor('sms'))->toThrow(LogicException::class, 'Keyring refuses codes shorter than 6 digits');
});

// What holds for email codes holds for any code factor: its codes' state is
// on the server, whatever copy of the session the browser sends.
describe('a browser that sends back an earlier copy of its session', function () {
    it('cannot sign in with a custom factor\'s code a second time', function () {
        Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'sms', 'name' => 'Phone', 'secret' => '+447700900001']);
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.send', 'sms'));
        $code = SmsCode::$sent['+447700900001'];
        $unspent = session()->all();

        $this->post(route('keyring.login.verify', 'sms'), ['code' => $code])->assertRedirect('/dashboard');
        $this->post('/logout');

        sendBackSession($unspent);

        $this->post(route('keyring.login.verify', 'sms'), ['code' => $code])->assertSessionHasErrors('code');
        $this->assertGuest();
    });

    it('cannot enroll one phone with the code sent to another', function () {
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1);
        $this->postJson(route('keyring.authenticators.store', 'sms'), ['phone' => '+447700900001'])->assertOk();
        $firstPhone = session()->all();

        $this->postJson(route('keyring.authenticators.store', 'sms'), ['phone' => '+447700900002'])->assertOk();

        sendBackSession($firstPhone);

        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
            ->postJson(route('keyring.authenticators.confirm', 'sms'), ['code' => SmsCode::$sent['+447700900002']])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['code' => __('keyring::keyring.invalid')]);

        expect($this->user->keyring->refresh()->of('sms'))->toBeEmpty();
    });
});
