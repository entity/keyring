<?php

use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Keyring\Changes\EmailChanges;
use Keyring\Enums\Assurance;
use Keyring\Events\AuthenticatorRemoved;
use Keyring\Facades\Keyring;
use Keyring\Models\Authenticator;
use Keyring\Models\PendingChange;
use Keyring\Notifications\ConfirmEmailChange;
use Keyring\Notifications\EmailChangeNotice;
use Keyring\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

beforeEach(function () {
    Notification::fake();
    $this->user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password', 'email_verified_at' => now()]);
});

/**
 * @return array{confirm: string, revert: string, current: ?string}
 */
function tokensFor(string $newAddress, string $currentAddress): array
{
    $confirm = $notice = null;

    Notification::assertSentTo(new AnonymousNotifiable, ConfirmEmailChange::class, function ($n, $c, $to) use ($newAddress, &$confirm) {
        return $to->routes['mail'] === $newAddress && ($confirm = $n->token);
    });
    Notification::assertSentTo(new AnonymousNotifiable, EmailChangeNotice::class, function ($n, $c, $to) use ($currentAddress, &$notice) {
        return $to->routes['mail'] === $currentAddress && ($notice = $n);
    });

    return ['confirm' => $confirm, 'revert' => $notice->revertToken, 'current' => $notice->confirmToken];
}

function requestChange(User $user, string $to, Assurance $as = Assurance::AAL1): PendingChange
{
    test()->actingAs($user)->withAssurance($as)
        ->postJson(route('keyring.email.store'), ['email' => $to])->assertOk();

    return PendingChange::query()->latest('id')->first();
}

/**
 * Confirm from both addresses (no second factor was proved, so both must).
 */
function confirmBoth(PendingChange $change, array $tokens): bool
{
    app(EmailChanges::class)->confirm($change, $tokens['current']);

    return app(EmailChanges::class)->confirm($change->fresh(), $tokens['confirm']);
}

it('does not change anything when an emailed link is only opened', function () {
    $change = requestChange($this->user, 'new@example.com');
    $tokens = tokensFor('new@example.com', 'taylor@example.com');

    $this->inertia()->get(route('keyring.email.confirm', [$change->id, $tokens['confirm']]))->assertOk()->assertJsonPath('component', 'auth/email-change');
    $this->inertia()->get(route('keyring.email.revert', [$change->id, $tokens['revert']]))->assertOk()->assertJsonPath('props.action', 'revert');

    expect($this->user->fresh()->email)->toBe('taylor@example.com')
        ->and($change->fresh()->isPending())->toBeTrue();
});

it('closes later changes when an earlier one is reverted', function () {
    $first = requestChange($this->user, 'b@example.com');
    $firstTokens = tokensFor('b@example.com', 'taylor@example.com');
    confirmBoth($first, $firstTokens);

    $this->user->refresh();
    Notification::fake();
    $second = requestChange($this->user, 'c@example.com');
    $secondTokens = tokensFor('c@example.com', 'b@example.com');
    confirmBoth($second, $secondTokens);
    expect($this->user->fresh()->email)->toBe('c@example.com');

    expect(app(EmailChanges::class)->revert($first->fresh(), $firstTokens['revert']))->toBeTrue();
    expect($this->user->fresh()->email)->toBe('taylor@example.com');

    expect(app(EmailChanges::class)->revert($second->fresh(), $secondTokens['revert']))->toBeFalse();
    expect($this->user->fresh()->email)->toBe('taylor@example.com');
});

it('cancels changes still pending when an earlier one is reverted', function () {
    $first = requestChange($this->user, 'b@example.com');
    $firstTokens = tokensFor('b@example.com', 'taylor@example.com');
    confirmBoth($first, $firstTokens);

    $this->user->refresh();
    Notification::fake();
    $second = requestChange($this->user, 'c@example.com');
    $secondTokens = tokensFor('c@example.com', 'b@example.com');

    app(EmailChanges::class)->revert($first->fresh(), $firstTokens['revert']);

    expect(confirmBoth($second->fresh(), $secondTokens))->toBeFalse()
        ->and($this->user->fresh()->email)->toBe('taylor@example.com');
});

it('does not apply a change once the address has moved on', function () {
    $change = requestChange($this->user, 'new@example.com');
    $tokens = tokensFor('new@example.com', 'taylor@example.com');

    Keyring::withoutProtection(fn () => $this->user->fresh()->update(['email' => 'support-set@example.com']));

    expect(confirmBoth($change, $tokens))->toBeFalse()
        ->and($this->user->fresh()->email)->toBe('support-set@example.com');
});

it('cannot be confirmed twice from stale copies', function () {
    $change = requestChange($this->user, 'new@example.com');
    $tokens = tokensFor('new@example.com', 'taylor@example.com');
    app(EmailChanges::class)->confirm($change, $tokens['current']);
    $stale = PendingChange::find($change->id);

    expect(app(EmailChanges::class)->confirm($change->fresh(), $tokens['confirm']))->toBeTrue()
        ->and(app(EmailChanges::class)->confirm($stale, $tokens['confirm']))->toBeFalse()
        ->and(PendingChange::find($change->id)->previous_value)->toBe('taylor@example.com');

    app(EmailChanges::class)->revert(PendingChange::find($change->id), $tokens['revert']);
    expect($this->user->fresh()->email)->toBe('taylor@example.com');
});

it('removes sign-in methods added since the change when it is reverted', function () {
    Event::fake([AuthenticatorRemoved::class]);
    $before = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['created_at' => now()->subDay()]);
    $change = requestChange($this->user, 'attacker@example.com', Assurance::AAL2);
    $tokens = tokensFor('attacker@example.com', 'taylor@example.com');

    $this->travel(1)->minutes();
    $planted = Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();

    confirmBoth($change, $tokens);
    app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']);

    expect(Authenticator::find($planted->id))->toBeNull()
        ->and(Authenticator::find($before->id))->not->toBeNull();
    Event::assertDispatched(AuthenticatorRemoved::class, fn (AuthenticatorRemoved $event) => $event->authenticator->is($planted));
});

it('cancels pending email changes when the password is reset', function () {
    $change = requestChange($this->user, 'attacker@example.com');
    $tokens = tokensFor('attacker@example.com', 'taylor@example.com');
    $this->post('/logout');

    $token = Password::broker()->createToken($this->user);
    $this->post(route('password.update'), [
        'token' => $token,
        'email' => 'taylor@example.com',
        'password' => 'correct horse battery staple',
        'password_confirmation' => 'correct horse battery staple',
    ])->assertRedirect(route('login'));

    expect(confirmBoth($change->fresh(), $tokens))->toBeFalse()
        ->and($this->user->fresh()->email)->toBe('taylor@example.com');
});

it('asks the current address to confirm when the second factor was only just added by this session', function () {
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');
    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => app(Google2FA::class)->getCurrentOtp($secret)])->assertOk();

    // Now that a second factor exists, the session has to use it to stay fresh.
    $this->travel(16)->minutes();
    $this->get(route('keyring.confirm.challenge'));
    $engine = app(Google2FA::class);
    $this->post(route('keyring.confirm.verify', 'totp'), ['code' => $engine->oathTotp($secret, $engine->getTimestamp() + 1)]);

    $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();

    expect(PendingChange::query()->latest('id')->first()->current_token)->not->toBeNull();
});

it('waives the current address confirmation for a second factor that predates the session', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['created_at' => now()->subDay()]);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => app(Google2FA::class)->getCurrentOtp($totp->secret)]);

    $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();

    expect(PendingChange::query()->latest('id')->first()->current_token)->toBeNull();
});

it('says a link was invalid when the token is wrong', function () {
    $change = requestChange($this->user, 'new@example.com');

    $this->post(route('keyring.email.confirm.store', [$change->id, 'wrong-token']))
        ->assertSessionHas('status', 'email-change-invalid');
});

it('cancels pending email changes on a password change, even keeping other sessions', function () {
    $change = requestChange($this->user, 'attacker@example.com');

    $this->putJson(route('user-password.update'), [
        'current_password' => 'password',
        'password' => 'a much longer passphrase',
        'password_confirmation' => 'a much longer passphrase',
        'sign_out_others' => false,
    ])->assertOk();

    expect($change->fresh()->cancelled_at)->not->toBeNull();
});
