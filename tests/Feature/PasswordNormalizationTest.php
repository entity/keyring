<?php

use Illuminate\Contracts\Validation\UncompromisedVerifier;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password as Broker;
use Illuminate\Support\Facades\Validator;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Features;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Signals\BreachedPassword;
use Keyring\Rules\CurrentPassword;
use Keyring\Support\PasswordRules;
use Keyring\Tests\Fixtures\User;

// The same password from two keyboards: "é" as one code point (NFC), and as
// an "e" followed by a combining accent (NFD).
const COMPOSED = "caf\u{00E9} au lait, s'il vous pla\u{00EE}t";
const DECOMPOSED = "cafe\u{0301} au lait, s'il vous plai\u{0302}t";

it('puts a password in nfc, and leaves alone what is not utf-8', function () {
    expect(COMPOSED)->not->toBe(DECOMPOSED)
        ->and(PasswordRules::normalize(DECOMPOSED))->toBe(COMPOSED)
        ->and(PasswordRules::normalize(COMPOSED))->toBe(COMPOSED)
        ->and(PasswordRules::normalize('plain ascii'))->toBe('plain ascii')
        ->and(PasswordRules::normalize(''))->toBe('')
        ->and(PasswordRules::normalize("\xff\xfe not utf-8"))->toBe("\xff\xfe not utf-8");
});

it('signs in with a password typed either way, whichever way it was set', function (string $set, string $typed) {
    $this->post('/register', ['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => $set, 'password_confirmation' => $set])
        ->assertRedirect('/dashboard');

    expect(Hash::check(COMPOSED, User::sole()->password))->toBeTrue();

    $this->post('/logout');
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => $typed])->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs(User::sole());
})->with([
    'set composed, typed decomposed' => [COMPOSED, DECOMPOSED],
    'set decomposed, typed composed' => [DECOMPOSED, COMPOSED],
    'set and typed decomposed' => [DECOMPOSED, DECOMPOSED],
]);

it('stores a reset password in nfc', function () {
    $user = taylor();

    $this->post(route('password.update'), [
        'token' => Broker::broker()->createToken($user),
        'email' => 'taylor@example.com',
        'password' => DECOMPOSED,
        'password_confirmation' => DECOMPOSED,
    ])->assertSessionHasNoErrors()->assertRedirect(route('login'));

    expect(Hash::check(COMPOSED, $user->fresh()->password))->toBeTrue();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => COMPOSED])->assertRedirect('/dashboard');
});

it('takes the current password typed either way on a change, and stores the new one in nfc', function () {
    $user = taylor(['password' => COMPOSED]);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => COMPOSED]);

    $this->putJson(route('user-password.update'), [
        'current_password' => DECOMPOSED,
        'password' => 'nouveau '.DECOMPOSED,
        // Composed here, as a password manager on another device might fill it.
        'password_confirmation' => 'nouveau '.COMPOSED,
    ])->assertOk();

    expect(Hash::check('nouveau '.COMPOSED, $user->fresh()->password))->toBeTrue();
});

it('confirms with the password typed either way', function () {
    $user = taylor(['password' => COMPOSED]);

    Route::get('/account', fn () => 'ok')->middleware(['web', 'auth', 'keyring.fresh:15m']);

    $this->actingAs($user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());
    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));

    $this->post(route('keyring.confirm.verify', 'password'), ['password' => DECOMPOSED])->assertRedirect('/account');
});

it('takes the password typed either way to remove the last second factor', function () {
    withFeatures(Features::all());

    // 15 characters composed, which is long enough alone, and 30 code points decomposed.
    $user = taylor(['password' => str_repeat("\u{00E9}", 15)]);
    $totp = Authenticator::factory()->totp()->for($user, 'authenticatable')->create();

    $this->actingAs($user)->withAssurance(Assurance::AAL2);
    $this->deleteJson(route('keyring.authenticators.destroy', $totp->id), ['password' => str_repeat("e\u{0301}", 15)])->assertOk();
});

it('measures the password in nfc before letting it stand alone', function () {
    withFeatures(Features::all());

    // 8 characters composed: too short alone, though the browser sent 16 code points.
    $user = taylor(['password' => str_repeat("\u{00E9}", 8)]);
    $totp = Authenticator::factory()->totp()->for($user, 'authenticatable')->create();

    $this->actingAs($user)->withAssurance(Assurance::AAL2);
    $this->deleteJson(route('keyring.authenticators.destroy', $totp->id), ['password' => str_repeat("e\u{0301}", 8)])
        ->assertJsonValidationErrors(['password' => __('keyring::keyring.password_too_short_alone', ['min' => 15])]);
});

it('checks the current password rule against the nfc form', function () {
    $user = taylor(['password' => COMPOSED]);

    $passes = fn (string $typed) => Validator::make(['current_password' => $typed], ['current_password' => [new CurrentPassword($user)]])->passes();

    expect($passes(DECOMPOSED))->toBeTrue()
        ->and($passes(COMPOSED))->toBeTrue()
        ->and($passes(COMPOSED.'x'))->toBeFalse();
});

it('measures a new password as it will be hashed, not as it was typed', function () {
    // 14 characters once composed, under the minimum of 15, though the
    // browser sent 28 code points.
    $short = str_repeat("e\u{0301}", 14);

    $this->post('/register', ['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => $short, 'password_confirmation' => $short])
        ->assertSessionHasErrors('password');

    expect(User::count())->toBe(0);
});

it('refuses a password bcrypt would cut short once it is in nfc', function () {
    // U+0958 is 3 bytes and has no composed form: NFC writes it as two
    // code points, 6 bytes. 20 of them are 60 bytes typed and 120 hashed.
    $grows = str_repeat("\u{0958}", 20);

    expect(strlen($grows))->toBe(60)
        ->and(strlen(PasswordRules::normalize($grows)))->toBe(120);

    $this->post('/register', ['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => $grows, 'password_confirmation' => $grows])
        ->assertSessionHasErrors(['password' => __('keyring::keyring.password_too_long', ['attribute' => 'password'])]);

    // And one already stored that way never matches on its first 72 bytes.
    expect(PasswordRules::forVerifying($grows, Hash::make('anything')))->not->toBe($grows)
        ->not->toBe(PasswordRules::normalize($grows));
});

it('looks a password up in the breach list as it was hashed', function () {
    $user = taylor(['password' => COMPOSED]);

    $verifier = new class implements UncompromisedVerifier
    {
        public array $seen = [];

        public function verify($data): bool
        {
            $this->seen[] = $data['value'];

            return true;
        }
    };

    $attempt = Attempt::start(Purpose::Login, $user, verifications: [new Verification('password', null, [Category::Knowledge], at: now()->getTimestamp())]);

    new BreachedPassword($verifier)->assess(new Assessment(Checkpoint::Login, Request::create('/login', 'POST', ['password' => DECOMPOSED]), $user, $attempt));

    expect($verifier->seen)->toBe([COMPOSED]);
});
