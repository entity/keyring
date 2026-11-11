<?php

use App\Notifications\Keyring\AuthenticatorAdded as AuthenticatorAddedNotice;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use Illuminate\Testing\TestResponse;
use Keyring\Concerns\HasKeyring;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Events\AuthenticatorAdded;
use Keyring\Events\AuthenticatorRemoved;
use Keyring\Events\RecoveryCodesGenerated;
use Keyring\Events\RecoveryCodeUsed;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Sessions\SessionAssurance;
use Keyring\Support\PasswordRules;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    $this->user = taylor();
    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
});

it('enrolls an authenticator app in two steps', function () {
    Event::fake([AuthenticatorAdded::class, RecoveryCodesGenerated::class]);

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'), ['name' => '1Password'])
        ->assertOk()
        ->assertJsonPath('factor', 'totp')
        ->assertJsonStructure(['enrollment' => ['secret', 'url', 'qr']])
        ->json('enrollment.secret');

    expect($this->user->keyring->refresh()->of('totp'))->toBeEmpty();

    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => '000000'])
        ->assertUnprocessable()
        ->assertJsonValidationErrors('code');

    $response = $this->postJson(route('keyring.authenticators.confirm', 'totp'), [
        'code' => totpCode($secret),
    ])->assertOk()->assertJsonPath('authenticator.name', '1Password');

    expect($response->json('recoveryCodes'))->toHaveCount(8);

    $keyring = $this->user->keyring->refresh();
    expect($keyring->of('totp'))->toHaveCount(1)
        ->and($keyring->of('totp')->first()->is_default)->toBeTrue()
        ->and($keyring->of('recovery'))->toHaveCount(1);

    Event::assertDispatched(AuthenticatorAdded::class);
    Event::assertDispatched(RecoveryCodesGenerated::class);
});

it('only hands out recovery codes automatically the first time', function () {
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');

    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])
        ->assertOk()
        ->assertJsonMissingPath('recoveryCodes')
        ->assertJsonPath('authenticator.name', 'Authenticator app');
});

it('regenerates recovery codes, replacing the old ones', function () {
    Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

    $codes = $this->postJson(route('keyring.authenticators.store', 'recovery'))->json('enrollment.codes');
    $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk();

    $recovery = $this->user->keyring->refresh()->of('recovery');
    expect($recovery)->toHaveCount(1)
        ->and($codes)->toHaveCount(8)
        ->and($recovery->first()->factor()->present($recovery->first())['remaining'])->toBe(8);
});

it('refuses recovery codes for a user with no second factor to back up', function () {
    $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();

    $this->postJson(route('keyring.authenticators.confirm', 'recovery'))
        ->assertUnprocessable()
        ->assertJsonValidationErrors(['authenticator' => 'back up another second factor']);

    expect($this->user->keyring->refresh()->all()->pluck('factor')->all())->toBe(['password']);
});

it('refuses to finish enrolling recovery codes once the second factor is gone', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();

    $totp->delete();

    $this->postJson(route('keyring.authenticators.confirm', 'recovery'))
        ->assertUnprocessable()
        ->assertJsonValidationErrors('authenticator');

    expect($this->user->keyring->refresh()->of('recovery'))->toBeEmpty();
});

it('enrolls recovery codes when there is a real second factor', function () {
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $codes = $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk()->json('enrollment.codes');
    $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk();

    expect($codes)->toHaveCount(8)
        ->and($this->user->keyring->refresh()->of('recovery'))->toHaveCount(1);
});

it('refuses to replace a used-up set with no second factor beside it', function () {
    Authenticator::factory()->recoveryCodes([])->for($this->user, 'authenticatable')->create();

    $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();
    $this->postJson(route('keyring.authenticators.confirm', 'recovery'))
        ->assertUnprocessable()
        ->assertJsonValidationErrors('authenticator');
});

it('issues new recovery codes when a factor is added and the old set has run out', function () {
    Event::fake([RecoveryCodesGenerated::class]);
    $old = Authenticator::factory()->recoveryCodes([])->for($this->user, 'authenticatable')->create();

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');
    $response = $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();

    $sets = $this->user->keyring->refresh()->of('recovery');
    expect($response->json('recoveryCodes'))->toHaveCount(8)
        ->and($sets)->toHaveCount(1)
        ->and($sets->first()->id)->not->toBe($old->id)
        ->and($sets->first()->factor()->present($sets->first())['remaining'])->toBe(8);

    Event::assertDispatched(RecoveryCodesGenerated::class);
});

it('does not touch a set that still has codes when a factor is added', function () {
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $set = Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');
    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])
        ->assertOk()
        ->assertJsonMissingPath('recoveryCodes');

    expect($this->user->keyring->refresh()->of('recovery')->pluck('id')->all())->toBe([$set->id]);
});

it('adds no recovery codes when that factor is not registered', function () {
    Keyring::factors([Password::class, Totp::class]);

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');

    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])
        ->assertOk()
        ->assertJsonMissingPath('recoveryCodes');
});

it('renames and picks the default', function () {
    $first = Authenticator::factory()->totp()->default()->for($this->user, 'authenticatable')->create();
    $second = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->patchJson(route('keyring.authenticators.update', $second->id), ['name' => 'Work phone', 'default' => true])
        ->assertOk()
        ->assertJsonPath('authenticator.name', 'Work phone');

    expect($first->fresh()->is_default)->toBeFalse()
        ->and($second->fresh()->is_default)->toBeTrue();
});

it('cannot touch someone else\'s authenticators', function () {
    $other = User::create(['name' => 'Other', 'email' => 'other@example.com', 'password' => 'password', 'email_verified_at' => now()]);
    $theirs = Authenticator::factory()->totp()->for($other, 'authenticatable')->create();

    $this->deleteJson(route('keyring.authenticators.destroy', $theirs->id))->assertNotFound();
});

it('removes an authenticator and drops recovery codes once nothing is left to recover', function () {
    Event::fake([AuthenticatorRemoved::class]);
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

    Keyring::withoutProtection(fn () => $this->user->update(['password' => 'a long enough passphrase']));

    $this->deleteJson(route('keyring.authenticators.destroy', $totp->id), ['password' => 'a long enough passphrase'])->assertOk();

    expect($this->user->keyring->refresh()->all()->pluck('factor')->all())->toBe(['password']);
    Event::assertDispatched(AuthenticatorRemoved::class);
});

it('checks the password is long enough on its own before removing the last second factor', function () {
    $phone = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $tablet = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    // Another second factor stays, so nothing more is asked.
    $this->deleteJson(route('keyring.authenticators.destroy', $phone->id))->assertOk();

    $this->deleteJson(route('keyring.authenticators.destroy', $tablet->id))->assertJsonValidationErrors(['password' => 'Enter your password']);
    $this->deleteJson(route('keyring.authenticators.destroy', $tablet->id), ['password' => 'password'])->assertJsonValidationErrors(['password' => 'at least 15 characters']);

    expect(Authenticator::find($tablet->id))->not->toBeNull();
});

it('refuses a password that is not a string when removing the last second factor', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->deleteJson(route('keyring.authenticators.destroy', $totp->id), ['password' => ['password']])
        ->assertJsonValidationErrors('password');

    expect(Authenticator::find($totp->id))->not->toBeNull();
});

it('gives an authenticator its usual name when the one sent is not text', function () {
    $this->postJson(route('keyring.authenticators.store', 'totp'), ['name' => ['x']])->assertOk();
    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => '000000', 'name' => ['x']])
        ->assertJsonValidationErrors('name');
});

it('limits password guesses when removing the last second factor', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    foreach (range(1, 6) as $guess) {
        $this->deleteJson(route('keyring.authenticators.destroy', $totp->id), ['password' => "guess {$guess}"])->assertUnprocessable();
    }

    $this->deleteJson(route('keyring.authenticators.destroy', $totp->id), ['password' => 'password'])->assertTooManyRequests();
});

it('refuses to remove the last factor the policy needs', function () {
    Keyring::require(Requirement::aal2());
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->deleteJson(route('keyring.authenticators.destroy', $totp->id))
        ->assertUnprocessable()
        ->assertJsonValidationErrors('authenticator');

    $second = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $this->deleteJson(route('keyring.authenticators.destroy', $totp->id))->assertOk();
    expect($second->fresh())->not->toBeNull();
});

it('needs a fresh verification to manage authenticators', function () {
    $this->travel(16)->minutes();

    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertStatus(423);
});

it('404s for factors that cannot be enrolled', function () {
    $this->postJson(route('keyring.authenticators.store', 'password'))->assertNotFound();
    $this->postJson(route('keyring.authenticators.store', 'nope'))->assertNotFound();
});

it('keeps the session verified when enrolling from an inertia page', function () {
    $this->inertia()->post(route('keyring.authenticators.store', 'totp'))->assertRedirect();
    $this->flushHeaders();

    // The enrollment details are flashed for the page, without wiping
    // Keyring's other session data (verifications, the session registry).
    expect(session('keyring.result.enrollment.secret'))->not->toBeNull();
    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk();
});

it('only allows the shorter password with a real second factor, not recovery codes alone', function () {
    $codes = Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

    expect($this->user->keyring->hasSecondFactor())->toBeFalse();
    expect(Validator::make(['password' => 'short pass', 'password_confirmation' => 'short pass'], ['password' => PasswordRules::for($this->user)])->fails())->toBeTrue();

    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    expect($this->user->keyring->refresh()->hasSecondFactor())->toBeTrue();
    expect(Validator::make(['password' => 'short pass', 'password_confirmation' => 'short pass'], ['password' => PasswordRules::for($this->user->fresh())])->fails())->toBeFalse();
});

it('tells the user when a sign-in method is added', function () {
    Notification::fake();

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');
    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();

    Notification::assertSentTo($this->user, AuthenticatorAddedNotice::class);
});

it('shows a name someone typed as plain text in the email, never as a link', function (string $name, string $html, string $text) {
    Notification::fake();
    sendNotifications();

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'), ['name' => $name])->json('enrollment.secret');
    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();

    $notice = Notification::sent($this->user, AuthenticatorAddedNotice::class)->sole();
    $mail = renderedMail($notice->toMail($this->user));

    expect($mail['html'])->not->toMatch('/<[^>]*(href|src)="[^"]*evil\.example/')
        ->toContain($html)
        ->and($mail['text'])->toContain($text);
})->with([
    'a link' => ['[Not you? Remove it here](https://evil.example/x)', '[Not you? Remove it here](https://evil.example/x)', '[Not you? Remove it here](https://evil.example/x)'],
    'an image' => ['![x](https://evil.example/p.png)', '![x](https://evil.example/p.png)', '![x](https://evil.example/p.png)'],
    'an autolink' => ['<https://evil.example/y>', '&lt;https://evil.example/y&gt;', '<https://evil.example/y>'],
    'an html tag' => ['<a href="https://evil.example/z">Hi</a>', '&lt;a href="https://evil.example/z"&gt;Hi&lt;/a&gt;', '<a href="https://evil.example/z">Hi</a>'],
    'emphasis and code' => ['**bold** _em_ `code`', '**bold** _em_ `code`', '**bold** _em_ `code`'],
    'a new line' => ["key\n\n# Heading", 'key # Heading', 'key # Heading'],
    'a legitimate name with punctuation' => ["Robert's [work] key", "Robert's [work] key", "Robert's [work] key"],
    'an ampersand' => ['R&D key', 'R&amp;D key', 'R&D key'],
]);

it('skips the notice for a model that can\'t be notified, instead of failing', function () {
    $account = UnnotifiableAccount::query()->findOrFail($this->user->getKey());
    $totp = Authenticator::factory()->totp()->for($account, 'authenticatable')->create();

    Notification::fake();

    AuthenticatorAdded::dispatch($account, $totp);

    expect(Keyring::hasNotification('authenticator_added'))->toBeTrue();
    Notification::assertNothingSent();
});

/**
 * Has a keyring but not Notifiable, like a second kind of account.
 */
#[Table(name: 'users')]
class UnnotifiableAccount extends Authenticatable
{
    use HasKeyring;
}

// NIST SP 800-63B-4, Sec. 3.1.2.1: recovery codes handed over in an online
// session need that session to be authenticated at AAL2.
describe('counting a new sign-in method as proved', function () {
    beforeEach(function () {
        Route::middleware(['web', 'auth', 'keyring:aal2'])->get('/billing', fn () => 'billing');
        Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->get('/account', fn () => 'danger zone');

        $this->post('/logout');
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
    });

    it('hands the first recovery codes to a session that has proved two factors', function () {
        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1);
        $before = session()->getId();

        $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');
        $response = $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();

        expect($response->json('recoveryCodes'))->toHaveCount(8)
            ->and(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2)
            ->and(app(SessionRegistry::class)->forUser($this->user)->sole()->assurance)->toBe(Assurance::AAL2)
            ->and(session()->getId())->not->toBe($before);

        $proved = collect(app(SessionAssurance::class)->all())->firstWhere('factor', 'totp');

        expect($proved->authenticator)->toBe($this->user->keyring->refresh()->of('totp')->sole()->id);
        $this->get('/billing')->assertOk();
    });

    it('counts nothing when the proof is wrong', function () {
        $this->postJson(route('keyring.authenticators.store', 'totp'));
        $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => '000000'])->assertUnprocessable();

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1)
            ->and(app(SessionAssurance::class)->all())->toHaveCount(1);
    });

    it('counts nothing for new recovery codes, which are only shown', function () {
        $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');
        $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();

        $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();
        $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk();

        expect(collect(app(SessionAssurance::class)->all())->pluck('factor')->all())->toBe(['password', 'totp']);
    });

    it('doesn\'t make the password any fresher', function () {
        $this->travel(10)->minutes();
        $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');
        $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();
        $this->get('/account')->assertOk();

        // The password was proved 16 minutes ago, the app's code six.
        $this->travel(6)->minutes();
        $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
    });

    it('counts a new passkey for what it proved, and no more', function () {
        $key = new VirtualAuthenticator;
        $options = $this->postJson(route('keyring.authenticators.store', 'passkey'))->json('enrollment.options');
        $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])->assertOk();

        $proved = collect(app(SessionAssurance::class)->all())->firstWhere('factor', 'passkey');

        expect($proved)
            ->categories->toBe([Category::Possession, Category::Inherence])
            ->phishingResistant->toBeTrue()
            ->attested->toBeFalse()
            ->and(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2);
    });
});

// NIST SP 800-63B-4, Sec. 4.2.1.1: after a recovery code is used, a new one
// is issued. Only the user can save new codes, so the app is told to send
// them to make a set.
describe('replacing recovery codes once one is used', function () {
    beforeEach(function () {
        $this->totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

        $this->post('/logout');
    });

    /**
     * Sign in with the password and a recovery code.
     */
    function signInWithRecoveryCode(string $code): TestResponse
    {
        test()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

        return test()->post(route('keyring.login.verify', 'recovery'), ['code' => $code]);
    }

    it('tells the app the user should make a new set, until they have', function () {
        Event::fake([RecoveryCodeUsed::class]);

        expect(Keyring::for($this->user)->shouldReplaceRecoveryCodes())->toBeFalse()
            ->and(Keyring::factor('recovery')->present(Keyring::for($this->user)->of('recovery')->sole()))->toMatchArray(['remaining' => 3, 'replace' => false]);

        signInWithRecoveryCode('wrong-code')->assertSessionHasErrors('code');
        expect(Keyring::for($this->user)->shouldReplaceRecoveryCodes())->toBeFalse();

        signInWithRecoveryCode('aaaaa-11111')->assertRedirect('/dashboard');
        expect(Keyring::for($this->user)->shouldReplaceRecoveryCodes())->toBeTrue()
            ->and(Keyring::factor('recovery')->present(Keyring::for($this->user)->of('recovery')->sole()))->toMatchArray(['remaining' => 2, 'replace' => true]);
        Event::assertDispatched(RecoveryCodeUsed::class, fn (RecoveryCodeUsed $event) => $event->remaining === 2);

        // It isn't a one-off notice: it's still there the next time.
        $this->post('/logout');
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret)])->assertRedirect('/dashboard');

        expect(Keyring::for($this->user)->shouldReplaceRecoveryCodes())->toBeTrue();
    });

    it('lets the session that used a code make the new set straight away, and stops asking', function () {
        signInWithRecoveryCode('aaaaa-11111')->assertRedirect('/dashboard');

        $codes = $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk()->json('enrollment.codes');
        $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk();

        expect($codes)->toHaveCount(8)
            ->and(Keyring::for($this->user)->shouldReplaceRecoveryCodes())->toBeFalse()
            ->and(Keyring::for($this->user)->of('recovery')->sole()->meta(RecoveryCodes::USED_AT))->toBeNull();
    });

    it('says so after a code is used to confirm, too', function () {
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());

        $this->post(route('keyring.authenticators.store', 'totp'))->assertRedirect(route('keyring.confirm.challenge'));
        $this->post(route('keyring.confirm.verify', 'recovery'), ['code' => 'bbbbb-22222']);

        expect(Keyring::for($this->user)->shouldReplaceRecoveryCodes())->toBeTrue();
    });
});
