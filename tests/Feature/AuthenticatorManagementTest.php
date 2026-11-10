<?php

use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Validator;
use Keyring\Concerns\HasKeyring;
use Keyring\Enums\Assurance;
use Keyring\Events\AuthenticatorAdded;
use Keyring\Events\AuthenticatorRemoved;
use Keyring\Events\RecoveryCodesGenerated;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\Totp;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Notifications\SecurityNotice;
use Keyring\Support\PasswordRules;
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

    Notification::assertSentTo($this->user, SecurityNotice::class, fn (SecurityNotice $notice) => $notice->type === 'authenticator_added');
});

it('shows a name someone typed as plain text in the email, never as a link', function (string $name, string $html, string $text) {
    Notification::fake();
    Keyring::sendSecurityNotices();

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'), ['name' => $name])->json('enrollment.secret');
    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();

    $notice = Notification::sent($this->user, SecurityNotice::class)->firstWhere('type', 'authenticator_added');
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

    AuthenticatorAdded::dispatch($account, $totp);

    expect(Keyring::sendsSecurityNotice('authenticator_added'))->toBeTrue();
});

/**
 * Has a keyring but not Notifiable, like a second kind of account.
 */
#[Table(name: 'users')]
class UnnotifiableAccount extends Authenticatable
{
    use HasKeyring;
}
