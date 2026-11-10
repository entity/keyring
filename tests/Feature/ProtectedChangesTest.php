<?php

use App\Notifications\Keyring\ConfirmEmailChange;
use App\Notifications\Keyring\EmailAddressInUse;
use App\Notifications\Keyring\EmailChangeNotice;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Testing\TestResponse;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Events\EmailChanged;
use Keyring\Events\EmailChangeReverted;
use Keyring\Events\PasswordChanged;
use Keyring\Events\PasswordReset;
use Keyring\Events\ProtectionBypassed;
use Keyring\Exceptions\ProtectedAttributeException;
use Keyring\Facades\Keyring;
use Keyring\Models\Authenticator;
use Keyring\Sessions\Sessions;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    Notification::fake();

    $this->user = taylor();
});

function sentTo(string $address, string $notification): object
{
    $sent = null;

    Notification::assertSentTo(new AnonymousNotifiable, $notification, function ($instance, $channels, $notifiable) use ($address, &$sent) {
        if ($notifiable->routes['mail'] === $address) {
            $sent = $instance;

            return true;
        }

        return false;
    });

    return $sent;
}

/**
 * Sign in for real with a password and a TOTP enrolled before this session,
 * the only kind of second factor that waives current-address confirmation.
 */
function signInWithTotp(User $user): void
{
    $totp = Authenticator::factory()->totp()->for($user, 'authenticatable')->create(['created_at' => now()->subMonth()]);

    test()->post('/login', ['email' => $user->email, 'password' => 'password']);
    test()->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)]);
}

/**
 * Open an emailed change link the way a person would: the GET shows a page,
 * and pressing its button POSTs back to the same URL.
 */
function follow(string $url): TestResponse
{
    test()->inertia()->get($url)->assertOk();
    test()->flushHeaders();

    return test()->post($url);
}

function linkIn(object $notification, string $text): string
{
    $mail = $notification->toMail(new AnonymousNotifiable);

    if ($mail->actionText === $text) {
        return $mail->actionUrl;
    }

    return collect([...$mail->introLines, ...$mail->outroLines])->first(fn ($line) => str_starts_with($line, 'http'));
}

describe('protected attributes', function () {
    it('refuses email and password changes outside a keyring flow', function () {
        expect(fn () => $this->user->fresh()->update(['email' => 'new@example.com']))->toThrow(ProtectedAttributeException::class)
            ->and(fn () => $this->user->fresh()->update(['password' => 'new-password']))->toThrow(ProtectedAttributeException::class);

        $this->user->fresh()->update(['name' => 'Taylor Otwell']);
        expect($this->user->fresh()->name)->toBe('Taylor Otwell');
    });

    it('has an escape hatch that announces itself', function () {
        Event::fake([ProtectionBypassed::class]);

        Keyring::withoutProtection(fn () => $this->user->update(['email' => 'admin-set@example.com']), reason: 'support ticket 42');

        expect($this->user->fresh()->email)->toBe('admin-set@example.com');
        Event::assertDispatched(ProtectionBypassed::class, fn ($event) => $event->reason === 'support ticket 42');
    });
});

it('protects the password under whatever name the model keeps it', function () {
    $user = new #[Table(name: 'users')] class extends User
    {
        protected $authPasswordName = 'name';
    };

    $account = $user->newQuery()->findOrFail($this->user->id);

    expect(Keyring::protectedAttributes($account))->toContain('name')->not->toContain('password')
        ->and(fn () => $account->update(['name' => 'Someone Else']))->toThrow(ProtectedAttributeException::class);
});

describe('changing email', function () {
    it('needs both addresses to confirm when there is no second factor', function () {
        Event::fake([EmailChanged::class]);
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

        $this->postJson(route('keyring.email.store'), ['email' => 'New@Example.com'])->assertOk();

        $this->getJson(route('keyring.email.show'))->assertJsonPath('pending.email', 'new@example.com')
            ->assertJsonPath('pending.needsCurrentConfirmation', true);

        follow(linkIn(sentTo('new@example.com', ConfirmEmailChange::class), 'Confirm email address'));
        expect($this->user->fresh()->email)->toBe('taylor@example.com');

        follow(linkIn(sentTo('taylor@example.com', EmailChangeNotice::class), 'Confirm the change'));
        expect($this->user->fresh()->email)->toBe('new@example.com')
            ->and($this->user->fresh()->email_verified_at)->not->toBeNull();

        Event::assertDispatched(EmailChanged::class);
    });

    it('only needs the new address to confirm when there is a second factor', function () {
        signInWithTotp($this->user);

        $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();

        $notice = sentTo('taylor@example.com', EmailChangeNotice::class);
        expect($notice->confirmUrl)->toBeNull();

        follow(linkIn(sentTo('new@example.com', ConfirmEmailChange::class), 'Confirm email address'));
        expect($this->user->fresh()->email)->toBe('new@example.com');
    });

    it('does not reveal that an address is taken', function () {
        User::create(['name' => 'Other', 'email' => 'taken@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

        $this->postJson(route('keyring.email.store'), ['email' => 'taken@example.com'])
            ->assertOk()
            ->assertJsonPath('status', 'email-change-requested');

        sentTo('taken@example.com', EmailAddressInUse::class);
        Notification::assertNotSentTo(new AnonymousNotifiable, ConfirmEmailChange::class);
    });

    it('looks the same to the account when the address is taken', function () {
        User::create(['name' => 'Other', 'email' => 'taken@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

        $this->postJson(route('keyring.email.store'), ['email' => 'taken@example.com'])->assertOk();

        $this->getJson(route('keyring.email.show'))
            ->assertJsonPath('pending.email', 'taken@example.com')
            ->assertJsonPath('pending.confirmed', false);

        // The current address could confirm, but the taken one never gets a link.
        $notice = sentTo('taylor@example.com', EmailChangeNotice::class);
        follow(linkIn($notice, 'Confirm this change'));

        expect($this->user->fresh()->email)->toBe('taylor@example.com');
    });

    it('lets the old address revert the change and signs everyone out', function () {
        Event::fake([EmailChangeReverted::class]);
        signInWithTotp($this->user);

        $this->postJson(route('keyring.email.store'), ['email' => 'attacker@example.com']);
        follow(linkIn(sentTo('attacker@example.com', ConfirmEmailChange::class), 'Confirm email address'));
        expect($this->user->fresh()->email)->toBe('attacker@example.com');

        $this->travel(3)->days();

        follow(linkIn(sentTo('taylor@example.com', EmailChangeNotice::class), 'Wasn\'t you'))
            ->assertRedirect(route('password.request'));

        expect($this->user->fresh()->email)->toBe('taylor@example.com')
            ->and(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty();
        Event::assertDispatched(EmailChangeReverted::class);
    });

    it('stops allowing reverts after the window', function () {
        signInWithTotp($this->user);

        $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com']);
        follow(linkIn(sentTo('new@example.com', ConfirmEmailChange::class), 'Confirm email address'));

        $this->travel(8)->days();

        follow(linkIn(sentTo('taylor@example.com', EmailChangeNotice::class), 'Wasn\'t you'));
        expect($this->user->fresh()->email)->toBe('new@example.com');
    });

    it('needs a fresh verification to start', function () {
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());

        $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertStatus(423);
    });
});

describe('changing password', function () {
    it('needs the current password and signs out other sessions', function () {
        Event::fake([PasswordChanged::class]);
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $other = app(Sessions::class)->registry();

        $this->putJson(route('user-password.update'), [
            'current_password' => 'wrong',
            'password' => 'correct horse battery staple',
            'password_confirmation' => 'correct horse battery staple',
        ])->assertJsonValidationErrors('current_password');

        $this->putJson(route('user-password.update'), [
            'current_password' => 'password',
            'password' => 'correct horse battery staple',
            'password_confirmation' => 'correct horse battery staple',
        ])->assertOk();

        expect(Hash::check('correct horse battery staple', $this->user->fresh()->password))->toBeTrue();
        Event::assertDispatched(PasswordChanged::class);
    });

    it('asks for longer passwords without a second factor', function () {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

        $this->putJson(route('user-password.update'), [
            'current_password' => 'password',
            'password' => 'short-ish-pw',
            'password_confirmation' => 'short-ish-pw',
        ])->assertJsonValidationErrors('password');
    });

    it('refuses passwords bcrypt would truncate', function () {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $long = str_repeat('ü', 40); // 80 bytes

        $this->putJson(route('user-password.update'), [
            'current_password' => 'password',
            'password' => $long,
            'password_confirmation' => $long,
        ])->assertJsonValidationErrors('password');
    });
});

describe('resetting password', function () {
    it('answers the same for unknown addresses', function () {
        $known = $this->postJson(route('password.email'), ['email' => 'taylor@example.com'])->json('status');
        $unknown = $this->postJson(route('password.email'), ['email' => 'nobody@example.com'])->json('status');

        expect($known)->toBe($unknown);
        Notification::assertSentTo($this->user, ResetPassword::class);
    });

    it('builds reset links from APP_URL, not the Host header', function () {
        config(['app.url' => 'https://app.example.com']);

        $this->withHeader('Host', 'evil.example')->post(route('password.email'), ['email' => 'taylor@example.com']);

        Notification::assertSentTo($this->user, ResetPassword::class, fn (ResetPassword $notification) => str_starts_with($notification->toMail($this->user)->actionUrl, 'https://app.example.com/reset-password/'));
    });

    it('resets without signing in, and signs out every session', function () {
        Event::fake([PasswordReset::class]);
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->post('/logout');

        $this->post(route('password.email'), ['email' => 'taylor@example.com']);

        $token = null;
        Notification::assertSentTo($this->user, ResetPassword::class, function ($notification) use (&$token) {
            $token = $notification->token;

            return true;
        });

        $this->inertia()->get(route('password.reset', ['token' => $token, 'email' => 'taylor@example.com']))
            ->assertHeader('Referrer-Policy', 'no-referrer');

        $this->post(route('password.update'), [
            'token' => $token,
            'email' => 'taylor@example.com',
            'password' => 'correct horse battery staple',
            'password_confirmation' => 'correct horse battery staple',
        ])->assertRedirect(route('login'));

        $this->assertGuest();
        expect(Hash::check('correct horse battery staple', $this->user->fresh()->password))->toBeTrue()
            ->and(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty();
        Event::assertDispatched(PasswordReset::class);
    });
});
