<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Keyring\Enrollment\Enrollment;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Factor;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Notifications\VerificationCode;
use Keyring\Sessions\SessionAssurance;
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

/**
 * A factor that is only something the user is: nothing they hold comes with it.
 */
class VoicePrint extends Factor
{
    public function key(): string
    {
        return 'voice';
    }

    public function categories(Authenticator $authenticator): array
    {
        return [Category::Inherence];
    }

    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        return $request->input('code') === 'my voice is my passport' ? $this->verified($authenticator) : null;
    }
}

/**
 * Sets aside the carrier a number is with when enrolling it: kept on the
 * server until the code comes back, never shown to the browser.
 */
class CarrierSmsCode extends SmsCode
{
    public function beginEnrollment(Authenticatable&Model $user, Request $request): Enrollment
    {
        return parent::beginEnrollment($user, $request)->with('carrier', $request->string('carrier')->value());
    }

    public function confirmEnrollment(Authenticatable&Model $user, Enrollment $enrollment, Request $request): ?Authenticator
    {
        return parent::confirmEnrollment($user, $enrollment, $request)?->withMeta('carrier', $enrollment->state('carrier'));
    }
}

beforeEach(function () {
    SmsCode::$sent = [];
    Keyring::factors([Password::class, Totp::class, EmailCode::asExtraStep(), SmsCode::class]);

    $this->user = taylor();
});

it('keeps what a custom code factor collects at enrollment', function () {
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

    $this->postJson(route('keyring.authenticators.store', 'sms'), ['password' => 'password', 'phone' => '+447700900001'])->assertOk();
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
        ->postJson(route('keyring.authenticators.store', 'totp'), ['password' => 'password'])
        ->assertJsonStructure(['enrollment' => ['qr']]);

    expect(json_decode(Crypt::decryptString(session('keyring.enrollment.totp')), true))->not->toHaveKey('props');
});

it('keeps what a custom factor sets aside at enrollment on the server until it is confirmed', function () {
    Keyring::factors([Password::class, CarrierSmsCode::class]);
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

    $this->postJson(route('keyring.authenticators.store', 'sms'), ['password' => 'password', 'phone' => '+447700900001', 'carrier' => 'Vodafone'])
        ->assertOk()
        ->assertDontSee('Vodafone');

    $this->postJson(route('keyring.authenticators.confirm', 'sms'), ['code' => SmsCode::$sent['+447700900001']])->assertOk();

    expect($this->user->keyring->refresh()->of('sms')->sole()->meta('carrier'))->toBe('Vodafone');
});

it('takes an enrollment kept in a shape it can\'t read back as one that has gone', function () {
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
        ->postJson(route('keyring.authenticators.store', 'totp'), ['password' => 'password'])->assertOk();

    // As a release that kept enrollments differently might have left it.
    $kept = json_decode(Crypt::decryptString(session('keyring.enrollment.totp')), true);
    session(['keyring.enrollment.totp' => Crypt::encryptString(json_encode([...$kept, 'state' => 'a secret'], JSON_THROW_ON_ERROR))]);

    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => '000000'])
        ->assertJsonValidationErrors(['code' => __('keyring::keyring.enrollment_expired')]);

    expect($this->user->keyring->refresh()->of('totp'))->toBeEmpty();
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

// NIST SP 800-63B-4 (Sec. 2.2.1) takes a biometric only with the
// authenticator it unlocks, so AAL2 needs something the user has.
describe('a factor that is nothing the user holds', function () {
    beforeEach(function () {
        Keyring::factors([Password::class, Totp::class, VoicePrint::class]);
        Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'voice', 'name' => 'Voice']);

        Route::middleware(['web', 'auth', 'keyring:aal2'])->get('/billing', fn () => 'billing');
        Route::middleware(['web', 'auth', 'keyring.enrolled'])->get('/app', fn () => 'app');
        config(['keyring.enrollment_url' => '/settings/security']);
    });

    it('is asked for beside the password, and leaves the session at aal1', function () {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));
        $this->post(route('keyring.login.verify', 'voice'), ['code' => 'my voice is my passport', 'trust' => true])->assertRedirect('/dashboard');

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1)
            ->and($this->user->devices()->whereNotNull('trusted_until')->count())->toBe(0);

        // Nothing it proved reaches AAL2, and the account has nothing that would.
        $this->get('/billing')->assertRedirect('/settings/security')->assertSessionHas('status', 'enroll-first');
        $this->get('/app')->assertRedirect('/settings/security');
    });

    it('doesn\'t count as the account\'s second factor', function () {
        $keyring = $this->user->keyring;

        expect($keyring->hasSecondFactor())->toBeFalse()
            ->and($keyring->canMeet(Requirement::aal2()))->toBeFalse()
            ->and($keyring->canMeet(Requirement::factors(2)))->toBeTrue();
    });

    it('is refused where the policy asks for aal2 outright', function () {
        Keyring::require(Requirement::aal2());

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

        $this->get(route('keyring.login.challenge'))
            ->assertRedirect('/login')
            ->assertSessionHasErrors(['email' => __('keyring::keyring.unavailable')]);
        $this->assertGuest();
    });

    it('reaches aal2 once something the user has is proved with it', function () {
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));

        // The voice print can't finish the sign in now, so it isn't offered.
        $this->post(route('keyring.login.verify', 'voice'), ['code' => 'my voice is my passport']);
        $this->assertGuest();

        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect('/dashboard');

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2);
        $this->get('/billing')->assertOk();
        $this->get('/app')->assertOk();
    });

    it('takes a recovery code in its place at a step-up, beside the password', function () {
        Keyring::factors([Password::class, VoicePrint::class, RecoveryCodes::class]);
        Authenticator::factory()->recoveryCodes(['aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->for($this->user, 'authenticatable')->create();
        Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->get('/account', fn () => 'danger zone');

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.verify', 'voice'), ['code' => 'my voice is my passport']);
        $this->travel(16)->minutes();

        $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
        $this->post(route('keyring.confirm.verify', 'recovery'), ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa']);
        $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));

        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password']);
        $this->get('/account')->assertOk();
    });
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
        $this->postJson(route('keyring.authenticators.store', 'sms'), ['password' => 'password', 'phone' => '+447700900001'])->assertOk();
        $firstPhone = session()->all();

        $this->postJson(route('keyring.authenticators.store', 'sms'), ['password' => 'password', 'phone' => '+447700900002'])->assertOk();

        sendBackSession($firstPhone);

        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
            ->postJson(route('keyring.authenticators.confirm', 'sms'), ['code' => SmsCode::$sent['+447700900002']])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['code' => __('keyring::keyring.invalid')]);

        expect($this->user->keyring->refresh()->of('sms'))->toBeEmpty();
    });
});
