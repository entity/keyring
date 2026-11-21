<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Keyring\Changes\AuthenticatorChanges;
use Keyring\Concerns\HasKeyring;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Events\AuthenticatorAdded;
use Keyring\Events\AuthenticatorRemoved;
use Keyring\Events\FactorVerified;
use Keyring\Events\RecoveryCodesGenerated;
use Keyring\Events\RecoveryCodeUsed;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Attempt;
use Keyring\Login\AttemptStore;
use Keyring\Login\Requirement;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Notifications\AuthenticatorAdded as AuthenticatorAddedNotice;
use Keyring\Notifications\RecoveryCodesGenerated as RecoveryCodesGeneratedNotice;
use Keyring\Sessions\SessionAssurance;
use Keyring\Support\PasswordRules;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\Tests\Fixtures\SingleSignOn;
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

// A sign-in method taken off the account stops counting in every session it
// signed in. It counts for nothing in a sign in that hasn't finished either.
describe('a sign-in method removed while a sign in that proved it is under way', function () {
    beforeEach(function () {
        Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');
        $this->totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        // Nobody is signed in yet.
        $this->app['auth']->forgetGuards();
        $this->flushSession();
    });

    it('ends a sign in that is waiting for its next step', function (Closure $remove) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));

        // One step further: the authenticator app proved, and more asked for.
        $store = app(AttemptStore::class);
        $attempt = $store->current(Purpose::Login);
        $attempt->record(new Verification('totp', $this->totp->id, [Category::Possession], at: now()->getTimestamp()));
        $store->save($attempt);

        expect($store->current(Purpose::Login))->not->toBeNull();

        $remove($this->totp);

        $this->get(route('keyring.login.challenge'))->assertRedirect(route('login'));
        expect(session()->has('keyring.attempt.login'))->toBeFalse();
        $this->assertGuest();
    })->with([
        // With another second factor beside it, so it isn't the last.
        'by its owner' => [function (Authenticator $totp) {
            Authenticator::factory()->passkey()->for($totp->user(), 'authenticatable')->create();

            app(AuthenticatorChanges::class)->remove($totp->user(), $totp->id);
        }],
        'however it went' => [fn (Authenticator $totp) => $totp->delete()],
    ]);

    it('ends a sign in it is removed in the middle of finishing', function () {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));

        // Between the code being checked and the session being registered.
        Event::listen(function (FactorVerified $event) {
            if ($event->verification->factor === 'totp') {
                $this->totp->delete();
            }
        });

        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret)])
            ->assertSessionHasErrors(['email' => __('auth.failed')]);

        $this->assertGuest();
        expect(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty();
        $this->get('/home')->assertRedirect('/login');
    });

    it('still finishes a sign in whose methods are all there', function () {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret)])->assertRedirect('/dashboard');

        $this->assertAuthenticatedAs($this->user);
    });
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

// Sent as a form: JSON can't carry text that isn't valid UTF-8.
it('refuses a name that isn\'t valid text, on a rename and when adding one', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['name' => 'Phone']);
    $json = ['Accept' => 'application/json'];

    $this->patch(route('keyring.authenticators.update', $totp->id), ['name' => "\xff"], $json)->assertJsonValidationErrors('name');
    $this->patchJson(route('keyring.authenticators.update', $totp->id), ['name' => "Work\0phone"])->assertJsonValidationErrors('name');
    expect($totp->fresh()->name)->toBe('Phone');

    $this->post(route('keyring.authenticators.store', 'totp'), ['name' => "\xff"], $json)->assertJsonValidationErrors('name');

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk()->json('enrollment.secret');
    $this->post(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret), 'name' => "Phone \xff"], $json)
        ->assertJsonValidationErrors('name');

    expect(Authenticator::query()->where('factor', 'totp')->count())->toBe(1);
});

it('keeps a name that isn\'t valid text as what can be read of it, however it is saved', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['name' => "Phone \xff"]);
    app(AuthenticatorChanges::class)->update($totp, ['name' => "Work \xfe"]);

    expect(mb_check_encoding($totp->fresh()->name, 'UTF-8'))->toBeTrue()
        ->and($totp->fresh()->name)->toStartWith('Work ');

    app(AuthenticatorChanges::class)->update($totp, ['name' => "Work\0phone"]);

    expect($totp->fresh()->name)->toBe('Workphone');
});

it('limits password guesses when removing the last second factor', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    foreach (range(1, 6) as $guess) {
        $this->deleteJson(route('keyring.authenticators.destroy', $totp->id), ['password' => "guess {$guess}"])->assertUnprocessable();
    }

    $this->deleteJson(route('keyring.authenticators.destroy', $totp->id), ['password' => 'password'])->assertTooManyRequests();
});

it('asks a user without a password for none when removing the last second factor', function () {
    Keyring::factors([Password::class, Totp::class, RecoveryCodes::class, SingleSignOn::class]);
    $this->user->forceFill(['password' => null])->saveQuietly();
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->actingAs($this->user->fresh())->withAssurance(Assurance::AAL2)
        ->deleteJson(route('keyring.authenticators.destroy', $totp->id))
        ->assertOk();

    expect(Authenticator::find($totp->id))->toBeNull()
        ->and($this->user->keyring->refresh()->all()->pluck('factor')->all())->toBe(['sso']);
});

it('gives a virtual authenticator its user\'s type and ID, so it can look them up again', function () {
    Keyring::factors([Password::class, Totp::class, RecoveryCodes::class, SingleSignOn::class]);

    $all = $this->user->keyring->all()->filter->isVirtual();

    expect($all->pluck('factor')->sort()->values()->all())->toBe(['password', 'sso']);

    foreach ($all as $authenticator) {
        $copy = $authenticator->withoutRelations();

        expect($authenticator->exists)->toBeFalse()
            ->and($authenticator->authenticatable_type)->toBe($this->user->getMorphClass())
            ->and($authenticator->authenticatable_id)->toBe($this->user->getKey())
            ->and($authenticator->owner()?->is($this->user))->toBeTrue()
            ->and($copy->relationLoaded('authenticatable'))->toBeFalse()
            ->and($copy->user()->is($this->user))->toBeTrue();
    }

    expect(Authenticator::query()->count())->toBe(0);
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
    expect(Keyring::result('enrollment.secret'))->not->toBeNull();
    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk();
});

// What a form or Inertia page is handed goes through the session store, and
// a store can be read without APP_KEY: a database, files, a backup.
it('keeps a secret being set up and new recovery codes out of the stored session', function () {
    $directory = sys_get_temp_dir().'/keyring-sessions-'.Str::random(8);
    mkdir($directory);
    config(['session.driver' => 'file', 'session.files' => $directory]);
    app('session')->forgetDrivers();
    app()->forgetInstance('session.store');
    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
    $stored = fn () => implode('', array_map(file_get_contents(...), glob($directory.'/*') ?: []));

    $this->inertia()->post(route('keyring.authenticators.store', 'totp'))->assertRedirect();
    $this->flushHeaders();
    $secret = Keyring::result('enrollment.secret');

    expect($secret)->toBeString()->not->toBe('')
        ->and($stored())->not->toBe('')->not->toContain($secret);

    $this->from('/settings')->post(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertRedirect('/settings');
    $codes = Keyring::result('recoveryCodes');

    expect($codes)->toBeArray()->not->toBeEmpty();

    foreach ($codes as $code) {
        expect($stored())->not->toContain($code);
    }

    // Read once, by the next request, like any flash.
    $this->get('/settings');
    $this->get('/settings');

    expect(Keyring::result())->toBeNull();
    File::deleteDirectory($directory);
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

it('tells the user when their recovery codes are replaced, unless the app turned the notice off', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $this->verifiedWith($totp);
    Notification::fake();
    Keyring::notifications(['recovery_codes_generated' => null]);

    $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();
    $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk();

    Notification::assertNothingSent();

    sendNotifications(['recovery_codes_generated']);

    $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();
    $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk();

    $notice = Notification::sent($this->user, RecoveryCodesGeneratedNotice::class)->sole();

    expect($notice->ip)->toBe('127.0.0.1')
        ->and(renderedMail($notice->toMail($this->user))['text'])->toContain('Any codes you saved before no longer work.');
});

it('tells them about the recovery codes that come with a first sign-in method too', function () {
    Notification::fake();
    sendNotifications(['recovery_codes_generated']);

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');
    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();

    Notification::assertSentToTimes($this->user, RecoveryCodesGeneratedNotice::class, 1);
    Notification::assertSentToTimes($this->user, AuthenticatorAddedNotice::class, 1);
});

it('sends nothing for a new name or a new default, which change nothing about how anyone signs in', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $this->verifiedWith($totp);
    Notification::fake();
    sendNotifications();

    $this->patchJson(route('keyring.authenticators.update', $totp), ['name' => 'Phone', 'default' => true])->assertOk();

    Notification::assertNothingSent();
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

// Laravel's "cookie" session driver keeps the session in the browser, which
// can send back an earlier copy: one that still holds an enrollment that has
// since been confirmed.
describe('a browser that sends back an earlier copy of its session', function () {
    it('cannot bring back recovery codes that were replaced', function () {
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        $this->verifiedWith($totp);

        $first = $this->postJson(route('keyring.authenticators.store', 'recovery'))->json('enrollment.codes');
        $unconfirmed = session()->all();
        $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk();

        $second = $this->postJson(route('keyring.authenticators.store', 'recovery'))->json('enrollment.codes');
        $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk();

        sendBackSession($unconfirmed);

        $this->actingAs($this->user)->verifiedWith($totp)
            ->postJson(route('keyring.authenticators.confirm', 'recovery'))
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['code' => __('keyring::keyring.enrollment_expired')]);

        $set = $this->user->keyring->refresh()->of('recovery')->sole();
        $attempt = Attempt::start(Purpose::Login, $this->user);

        expect(Keyring::factor('recovery')->verify($attempt, $set, Request::create('/', 'POST', ['code' => $first[0]])))->toBeNull()
            ->and(Keyring::factor('recovery')->verify($attempt, $set, Request::create('/', 'POST', ['code' => $second[0]])))->not->toBeNull();
    });

    it('cannot add the same authenticator app twice from one enrollment', function () {
        $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');
        $unconfirmed = session()->all();
        $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();

        sendBackSession($unconfirmed);

        $this->actingAs($this->user)->withAssurance(Assurance::AAL2)
            ->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret, 1)])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['code' => __('keyring::keyring.enrollment_expired')]);

        expect($this->user->keyring->refresh()->of('totp'))->toHaveCount(1);
    });
});

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

        signInWithRecoveryCode('aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa')->assertRedirect('/dashboard');
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
        signInWithRecoveryCode('aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa')->assertRedirect('/dashboard');

        $codes = $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk()->json('enrollment.codes');
        $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk();

        expect($codes)->toHaveCount(8)
            ->and(Keyring::for($this->user)->shouldReplaceRecoveryCodes())->toBeFalse()
            ->and(Keyring::for($this->user)->of('recovery')->sole()->meta(RecoveryCodes::USED_AT))->toBeNull();
    });

    it('says so after a code is used to confirm, too', function () {
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());

        $this->post(route('keyring.authenticators.store', 'totp'))->assertRedirect(route('keyring.confirm.challenge'));
        $this->post(route('keyring.confirm.verify', 'recovery'), ['code' => 'bbbb-bbbb-bbbb-bbbb-bbbb-bbbb-bb']);

        expect(Keyring::for($this->user)->shouldReplaceRecoveryCodes())->toBeTrue();
    });
});

// OWASP's Passkey Security Cheat Sheet has a page that manages credentials
// show when each was created and last used.
describe('what a sign-in method shows of itself', function () {
    it('says when it was added and when it was last used, as a settings page needs', function (Closure $make) {
        Keyring::factors([Password::class, Totp::class, RecoveryCodes::class, WebAuthn::passkeys(), WebAuthn::securityKeys()]);
        $this->travelTo('2026-11-08 09:30:00');
        $authenticator = $make($this->user);

        expect($authenticator->factor()->present($authenticator))
            ->toMatchArray(['createdAt' => '2026-11-08T09:30:00+00:00', 'lastUsedAt' => null]);

        $this->travelTo('2026-11-10 17:45:10');
        $authenticator->markAsUsed();

        expect($authenticator->factor()->present($authenticator))
            ->toMatchArray(['id' => $authenticator->id, 'createdAt' => '2026-11-08T09:30:00+00:00', 'lastUsedAt' => '2026-11-10T17:45:10+00:00']);
    })->with([
        'a passkey' => [fn (User $user) => Authenticator::factory()->passkey()->for($user, 'authenticatable')->create()],
        'a security key' => [fn (User $user) => Authenticator::factory()->securityKey()->for($user, 'authenticatable')->create()],
        'an authenticator app' => [fn (User $user) => Authenticator::factory()->totp()->for($user, 'authenticatable')->create()],
        'recovery codes' => [fn (User $user) => Authenticator::factory()->recoveryCodes()->for($user, 'authenticatable')->create()],
    ]);

    it('has neither for the password, which has no record of its own', function () {
        $password = $this->user->keyring->of('password')->sole();

        expect($password->factor()->present($password))->toMatchArray(['id' => null, 'createdAt' => null, 'lastUsedAt' => null]);
    });

    it('says so in the answer to adding or renaming one', function () {
        $this->travelTo('2026-11-08 09:30:00');
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

        $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk()->json('enrollment.secret');
        $added = $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])
            ->assertOk()
            ->assertJsonPath('authenticator.createdAt', '2026-11-08T09:30:00+00:00');

        $this->withAssurance(Assurance::AAL2)->patchJson(route('keyring.authenticators.update', $added->json('authenticator.id')), ['name' => 'Phone'])
            ->assertOk()
            ->assertJsonPath('authenticator.name', 'Phone')
            ->assertJsonPath('authenticator.createdAt', '2026-11-08T09:30:00+00:00');
    });

    // Only a password has been proved there, and whoever has it has no
    // call to learn when its owner last signed in.
    it('keeps both off the challenge page', function () {
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['last_used_at' => now()]);
        Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create(['last_used_at' => now()]);

        $this->post('/logout');
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));

        $props = $this->inertia()->get(route('keyring.login.challenge'))->assertOk()->json('props');

        expect($props['authenticator'])->toBe(['factor' => 'totp', 'id' => $totp->id, 'name' => $totp->name])
            ->and($props['alternatives'])->toHaveCount(1)
            ->and($props['alternatives'][0])->toHaveKeys(['factor', 'id', 'name', 'remaining', 'replace'])->not->toHaveKeys(['createdAt', 'lastUsedAt']);
    });
});
