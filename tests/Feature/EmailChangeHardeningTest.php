<?php

use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use Keyring\Changes\EmailChanges;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Enums\EmailConfirmation;
use Keyring\Events\AuthenticatorRemoved;
use Keyring\Exceptions\ProtectedAttributeException;
use Keyring\Exceptions\ReservedAddressException;
use Keyring\Facades\Keyring;
use Keyring\Features;
use Keyring\Models\Authenticator;
use Keyring\Models\PendingChange;
use Keyring\Notifications\ConfirmEmailChange;
use Keyring\Notifications\EmailAddressInUse;
use Keyring\Notifications\EmailChangeNotice;
use Keyring\Notifications\SecurityNotice;
use Keyring\Rules\UnreservedAddress;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\Sessions;
use Keyring\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

beforeEach(function () {
    Notification::fake();
    $this->user = taylor();
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
function confirmBoth(PendingChange $change, array $tokens): EmailConfirmation
{
    app(EmailChanges::class)->confirm($change, $tokens['current']);

    return app(EmailChanges::class)->confirm($change->fresh(), $tokens['confirm']);
}

it('shows the address in the change notice as plain text', function (string $value, string $shown) {
    $change = requestChange($this->user, 'new@example.com');
    $change->value = $value;

    $mail = renderedMail(new EmailChangeNotice($change, 'revert-token')->toMail(new AnonymousNotifiable));

    expect($mail['html'])->not->toMatch('/<[^>]*(href|src)="[^"]*evil\.example/')
        ->toContain($shown)
        ->and($mail['text'])->toContain($shown);
})->with([
    'a link in the domain' => ['a@[x](https://evil.example/e)', 'a•••@[x](https://evil.example/e)'],
    'a normal address' => ['new@example.com', 'n•••@example.com'],
]);

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

    expect(confirmBoth($second->fresh(), $secondTokens))->toBe(EmailConfirmation::Invalid)
        ->and($this->user->fresh()->email)->toBe('taylor@example.com');
});

it('does not apply a change once the address has moved on', function () {
    $change = requestChange($this->user, 'new@example.com');
    $tokens = tokensFor('new@example.com', 'taylor@example.com');

    Keyring::withoutProtection(fn () => $this->user->fresh()->update(['email' => 'support-set@example.com']));

    expect(confirmBoth($change, $tokens))->toBe(EmailConfirmation::Invalid)
        ->and($this->user->fresh()->email)->toBe('support-set@example.com');
});

it('cannot be confirmed twice from stale copies', function () {
    $change = requestChange($this->user, 'new@example.com');
    $tokens = tokensFor('new@example.com', 'taylor@example.com');
    app(EmailChanges::class)->confirm($change, $tokens['current']);
    $stale = PendingChange::find($change->id);

    expect(app(EmailChanges::class)->confirm($change->fresh(), $tokens['confirm']))->toBe(EmailConfirmation::Applied)
        ->and(app(EmailChanges::class)->confirm($stale, $tokens['confirm']))->toBe(EmailConfirmation::Invalid)
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

    expect(confirmBoth($change->fresh(), $tokens))->toBe(EmailConfirmation::Invalid)
        ->and($this->user->fresh()->email)->toBe('taylor@example.com');
});

it('ends reset links for the old address when the email changes, and they do not return with a revert', function () {
    $token = Password::broker()->createToken($this->user);

    $change = requestChange($this->user, 'new@example.com');
    $tokens = tokensFor('new@example.com', 'taylor@example.com');
    expect(confirmBoth($change, $tokens))->toBe(EmailConfirmation::Applied)
        ->and(Password::broker()->tokenExists(new User(['email' => 'taylor@example.com']), $token))->toBeFalse();

    // A link sent to the new address goes when the change is undone, too.
    $sentToNew = Password::broker()->createToken($this->user->fresh());
    expect(app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']))->toBeTrue()
        ->and(Password::broker()->tokenExists(new User(['email' => 'new@example.com']), $sentToNew))->toBeFalse();

    $this->post('/logout');
    $this->post(route('password.update'), ['token' => $token, 'email' => 'taylor@example.com', 'password' => 'attacker set passphrase', 'password_confirmation' => 'attacker set passphrase'])
        ->assertSessionHasErrors('email');
    expect(Hash::check('password', $this->user->fresh()->password))->toBeTrue();
});

it('leaves a reset link for the new address working after the email changes', function () {
    $change = requestChange($this->user, 'new@example.com');
    confirmBoth($change, tokensFor('new@example.com', 'taylor@example.com'));
    $token = Password::broker()->createToken($this->user->fresh());

    $this->post('/logout');
    $this->post(route('password.update'), ['token' => $token, 'email' => 'new@example.com', 'password' => 'a brand new passphrase', 'password_confirmation' => 'a brand new passphrase'])
        ->assertRedirect(route('login'));

    expect(Hash::check('a brand new passphrase', $this->user->fresh()->password))->toBeTrue();
});

it('asks the current address to confirm when the second factor was only just added by this session', function () {
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');
    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();

    // Now that a second factor exists, the session has to use it to stay fresh.
    $this->travel(16)->minutes();
    $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertStatus(423);
    $this->get(route('keyring.confirm.challenge'));
    $engine = app(Google2FA::class);
    $this->post(route('keyring.confirm.verify', 'totp'), ['code' => $engine->oathTotp($secret, $engine->getTimestamp() + 1)]);
    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password']);

    $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();

    expect(PendingChange::query()->latest('id')->first()->current_token)->not->toBeNull();
});

it('waives the current address confirmation for a second factor that predates the session', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['created_at' => now()->subDay()]);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)]);

    $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();

    expect(PendingChange::query()->latest('id')->first()->current_token)->toBeNull();
});

it('keeps the revert link working after signing out everywhere else cancels the change', function () {
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->postJson(route('keyring.email.store'), ['email' => 'attacker@example.com'])->assertOk();
    $change = PendingChange::sole();
    $tokens = tokensFor('attacker@example.com', 'taylor@example.com');

    $this->deleteJson(route('keyring.devices.destroy-others'))->assertOk();
    $planted = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    expect($change->fresh()->isPending())->toBeFalse()
        ->and(confirmBoth($change->fresh(), $tokens))->toBe(EmailConfirmation::Invalid);

    $this->post(route('keyring.email.revert.store', [$change->id, $tokens['revert']]))
        ->assertSessionHas('status', 'email-change-reverted');

    expect($change->fresh()->reverted_at)->not->toBeNull()
        ->and(Authenticator::find($planted->id))->toBeNull()
        ->and($this->user->fresh()->email)->toBe('taylor@example.com');
});

it('does not revert a change its owner cancelled', function () {
    $change = requestChange($this->user, 'new@example.com');
    $tokens = tokensFor('new@example.com', 'taylor@example.com');

    $this->deleteJson(route('keyring.email.destroy'))->assertOk();

    expect(app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']))->toBeFalse();
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

describe('the address a change replaced', function () {
    beforeEach(function () {
        $change = requestChange($this->user, 'attacker@example.com');
        confirmBoth($change, $this->tokens = tokensFor('attacker@example.com', 'taylor@example.com'));
        $this->change = $change->fresh();
    });

    it('cannot be registered while the change can be reverted', function () {
        $this->post('/logout');

        $this->post('/register', [
            'name' => 'Someone',
            'email' => 'Taylor@Example.com',
            'password' => 'correct horse battery staple',
            'password_confirmation' => 'correct horse battery staple',
        ])->assertSessionHasErrors(['email' => 'The email has already been taken.']);

        expect(User::count())->toBe(1);
    });

    it('cannot be moved to by another account', function () {
        $other = taylor(['email' => 'other@example.com']);
        $this->flushSession();

        $this->actingAs($other)->withAssurance(Assurance::AAL1)
            ->postJson(route('keyring.email.store'), ['email' => 'taylor@example.com'])->assertOk();

        expect(PendingChange::query()->ownedBy($other)->exists())->toBeFalse();
        Notification::assertSentTo(new AnonymousNotifiable, EmailAddressInUse::class, fn ($n, $c, $to) => $to->routes['mail'] === 'taylor@example.com');
    });

    it('cannot be given to another user however they are saved', function () {
        expect(fn () => taylor())->toThrow(ReservedAddressException::class);

        $other = taylor(['email' => 'other@example.com']);

        // Protected attributes are checked first, and lifting that protection
        // doesn't lift the reservation.
        expect(fn () => $other->update(['email' => 'taylor@example.com']))->toThrow(ProtectedAttributeException::class)
            ->and(fn () => Keyring::withoutProtection(fn () => $other->update(['email' => 'taylor@example.com'])))->toThrow(ReservedAddressException::class);
    });

    it('is refused by the validation rule, whatever its case', function () {
        expect(Validator::make(['email' => 'TAYLOR@example.com'], ['email' => new UnreservedAddress])->fails())->toBeTrue()
            ->and(Validator::make(['email' => 'someone@example.com'], ['email' => new UnreservedAddress])->fails())->toBeFalse();
    });

    it('stays reserved after APP_KEY is rotated', function () {
        config(['app.previous_keys' => [config('app.key')], 'app.key' => 'base64:'.base64_encode(random_bytes(32))]);

        expect(fn () => taylor())->toThrow(ReservedAddressException::class);
    });

    it('still goes back to its owner when the change is reverted', function () {
        expect(app(EmailChanges::class)->revert($this->change, $this->tokens['revert']))->toBeTrue()
            ->and($this->user->fresh()->email)->toBe('taylor@example.com');
    });

    it('is free again once the change can no longer be reverted', function () {
        $this->travel(8)->days();

        expect(taylor()->exists)->toBeTrue();
    });
});

/**
 * A signed-in session on another device, as the registry holds it.
 */
function otherSession(User $user, string $id = 'other-session'): string
{
    $now = now()->getTimestamp();

    app(SessionRegistry::class)->save(new RegisteredSession(
        id: $id,
        userId: (string) $user->getKey(),
        guard: 'web',
        deviceId: null,
        assurance: Assurance::AAL1,
        ip: '198.51.100.1',
        userAgent: 'Other device',
        authenticatedAt: $now,
        lastActivityAt: $now,
        expiresAt: $now + 86400,
    ));

    return $id;
}

describe('whose verification waives the current address', function () {
    it('still asks the current address when the session verified someone else\'s factor', function () {
        $admin = taylor(['email' => 'admin@example.com']);
        $totp = Authenticator::factory()->totp()->for($admin, 'authenticatable')->create(['created_at' => now()->subDay()]);

        $this->post('/login', ['email' => 'admin@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)]);
        $this->travel(1)->minutes();

        // An app's own "become this user", without clearing what the session proved.
        Route::middleware(['web', 'auth'])->post('/impersonate/{id}', function (string $id) {
            session()->forget(Sessions::KEY);
            Auth::guard('web')->login(User::findOrFail($id));

            return 'ok';
        });
        $this->post('/impersonate/'.$this->user->getKey())->assertOk();
        $this->travel(1)->seconds();

        $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();

        expect(PendingChange::query()->ownedBy($this->user)->sole()->current_token)->not->toBeNull();
    });
});

describe('applying a change', function () {
    it('ends the account\'s other sessions and keeps the one that confirmed', function () {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();
        $change = PendingChange::sole();
        $tokens = tokensFor('new@example.com', 'taylor@example.com');
        $current = app(Sessions::class)->current(request())->id;
        $other = otherSession($this->user);

        $this->post(route('keyring.email.confirm.store', [$change->id, $tokens['current']]));
        $this->post(route('keyring.email.confirm.store', [$change->id, $tokens['confirm']]));

        expect($this->user->fresh()->email)->toBe('new@example.com')
            ->and(app(SessionRegistry::class)->find($other)->revokedAt)->not->toBeNull()
            ->and(app(SessionRegistry::class)->find($current)->revokedAt)->toBeNull();

        $this->assertAuthenticatedAs($this->user->fresh());
    });

    it('gives the confirming browser a new session id', function () {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();
        $change = PendingChange::sole();
        $tokens = tokensFor('new@example.com', 'taylor@example.com');
        $this->post(route('keyring.email.confirm.store', [$change->id, $tokens['current']]));
        $before = session()->getId();

        $this->withCookie(config('session.cookie'), $before)
            ->post(route('keyring.email.confirm.store', [$change->id, $tokens['confirm']]))->assertSessionHas('status', 'email-changed');

        expect(session()->getId())->not->toBe($before)
            ->and(session()->getId())->not->toBeEmpty();
    });

    it('signs out everywhere when confirmed by a browser that is not signed in as the account', function () {
        $change = requestChange($this->user, 'new@example.com');
        $tokens = tokensFor('new@example.com', 'taylor@example.com');
        $other = otherSession($this->user);

        $this->flushSession();
        Auth::guard('web')->logout();
        Auth::forgetGuards();
        $this->withSession([Sessions::KEY => $other]); // left behind, so only the guard says who this is

        $this->post(route('keyring.email.confirm.store', [$change->id, $tokens['current']]));
        $this->post(route('keyring.email.confirm.store', [$change->id, $tokens['confirm']]));

        expect($this->user->fresh()->email)->toBe('new@example.com')
            ->and(app(SessionRegistry::class)->find($other)->revokedAt)->not->toBeNull();
    });

    it('does not keep the session of a browser signed in as someone else', function () {
        $change = requestChange($this->user, 'new@example.com');
        $tokens = tokensFor('new@example.com', 'taylor@example.com');
        $other = otherSession($this->user);

        $stranger = taylor(['email' => 'stranger@example.com']);
        $this->flushSession();
        Auth::guard('web')->logout();
        Auth::forgetGuards();
        $this->actingAs($stranger);

        $this->post(route('keyring.email.confirm.store', [$change->id, $tokens['current']]));
        $before = session()->getId();
        $this->withCookie(config('session.cookie'), $before)->post(route('keyring.email.confirm.store', [$change->id, $tokens['confirm']]));

        expect($this->user->fresh()->email)->toBe('new@example.com')
            ->and(app(SessionRegistry::class)->find($other)->revokedAt)->not->toBeNull()
            ->and(session()->getId())->toBe($before);
    });

    it('leaves other sessions alone when the app opts out', function () {
        config(['keyring.email_changes.sign_out_others' => false]);
        $change = requestChange($this->user, 'new@example.com');
        $tokens = tokensFor('new@example.com', 'taylor@example.com');
        $other = otherSession($this->user);

        confirmBoth($change, $tokens);

        expect(app(SessionRegistry::class)->find($other)->revokedAt)->toBeNull();
    });

    it('does not touch device tables when devices are off', function () {
        withFeatures([Features::emailChanges()]);
        $change = requestChange($this->user, 'new@example.com');
        $tokens = tokensFor('new@example.com', 'taylor@example.com');
        DB::enableQueryLog();

        confirmBoth($change, $tokens);

        expect(collect(DB::getQueryLog())->pluck('query')->filter(fn (string $query) => str_contains($query, 'keyring_devices')))->toBeEmpty()
            ->and($this->user->fresh()->email)->toBe('new@example.com');
    });

    it('tells both addresses when the app has opted in', function () {
        Keyring::notify();
        $change = requestChange($this->user, 'new@example.com');
        $tokens = tokensFor('new@example.com', 'taylor@example.com');

        confirmBoth($change, $tokens);

        Notification::assertSentTo($this->user, SecurityNotice::class, fn (SecurityNotice $notice) => $notice->type === 'email_changed');
        Notification::assertSentTo(new AnonymousNotifiable, SecurityNotice::class, fn (SecurityNotice $notice, $channels, $to) => $to->routes['mail'] === 'taylor@example.com' && $notice->type === 'email_changed');
    });

    it('sends no notice unless the app opted in', function () {
        $change = requestChange($this->user, 'new@example.com');
        $tokens = tokensFor('new@example.com', 'taylor@example.com');

        confirmBoth($change, $tokens);

        Notification::assertNotSentTo($this->user, SecurityNotice::class);
        Notification::assertNotSentTo(new AnonymousNotifiable, SecurityNotice::class);
    });

    it('tells both addresses when an applied change is reverted', function () {
        Keyring::notify();
        $change = requestChange($this->user, 'new@example.com');
        $tokens = tokensFor('new@example.com', 'taylor@example.com');
        confirmBoth($change, $tokens);

        app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']);

        Notification::assertSentTo($this->user, SecurityNotice::class, fn (SecurityNotice $notice) => $notice->type === 'email_change_reverted');
        Notification::assertSentTo(new AnonymousNotifiable, SecurityNotice::class, fn (SecurityNotice $notice, $channels, $to) => $to->routes['mail'] === 'new@example.com' && $notice->type === 'email_change_reverted');
    });

    it('keeps an app\'s own via() away from an address that has no user', function () {
        Keyring::notify();
        Keyring::securityNoticesUsing(PerUserChannelsNotice::class);
        $change = requestChange($this->user, 'new@example.com');
        $tokens = tokensFor('new@example.com', 'taylor@example.com');

        $this->post(route('keyring.email.confirm.store', [$change->id, $tokens['current']]));
        $this->post(route('keyring.email.confirm.store', [$change->id, $tokens['confirm']]))->assertSessionHas('status', 'email-changed');
        $this->post(route('keyring.email.revert.store', [$change->id, $tokens['revert']]))->assertSessionHas('status', 'email-change-reverted');

        Notification::assertSentTo($this->user, PerUserChannelsNotice::class, fn (SecurityNotice $notice) => $notice->type === 'email_changed');
        Notification::assertSentTo(new AnonymousNotifiable, SecurityNotice::class, fn (SecurityNotice $notice, $channels, $to) => $to->routes['mail'] === 'taylor@example.com' && $notice->type === 'email_changed' && $channels === ['mail']);
        Notification::assertSentTo(new AnonymousNotifiable, SecurityNotice::class, fn (SecurityNotice $notice, $channels, $to) => $to->routes['mail'] === 'new@example.com' && $notice->type === 'email_change_reverted' && $channels === ['mail']);
    });

    it('does not mail the address that never confirmed when a pending change is reverted', function () {
        Keyring::notify();
        $change = requestChange($this->user, 'attacker@example.com');
        $tokens = tokensFor('attacker@example.com', 'taylor@example.com');

        app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']);

        Notification::assertSentTo($this->user, SecurityNotice::class, fn (SecurityNotice $notice) => $notice->type === 'email_change_reverted');
        Notification::assertNotSentTo(new AnonymousNotifiable, SecurityNotice::class, fn (SecurityNotice $notice, $channels, $to) => $to->routes['mail'] === 'attacker@example.com');
    });
});

/**
 * The per-user via() that docs/security-log-and-emails.md suggests.
 */
class PerUserChannelsNotice extends SecurityNotice
{
    public function via(object $notifiable): array
    {
        return $notifiable->slack_webhook ? ['mail', 'slack'] : ['mail'];
    }
}
