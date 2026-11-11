<?php

declare(strict_types=1);

use App\Notifications\Keyring\AccountLocked;
use App\Notifications\Keyring\ConfirmEmailChange;
use App\Notifications\Keyring\EmailChangeNotice;
use App\Notifications\Keyring\NewDevice;
use App\Notifications\Keyring\PasswordChanged;
use App\Notifications\Keyring\RecoveryCodesGenerated as RecoveryCodesGeneratedNotice;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Illuminate\Testing\TestResponse;
use Keyring\Enums\Assurance;
use Keyring\Events\AccountLocked as AccountLockedEvent;
use Keyring\Events\PasswordChanged as PasswordChangedEvent;
use Keyring\Events\RecoveryCodesGenerated;
use Keyring\Models\Authenticator;
use Keyring\Models\PendingChange;
use Keyring\Models\SecurityEvent;
use Keyring\Tests\Fixtures\User;

// None of this mail is a guess at anything, so the limits on guessing never
// count it. Each kind has a count of its own per recipient instead.
beforeEach(function () {
    Notification::fake();
    sendNotifications();

    $this->user = taylor();
});

/**
 * Sign in from a browser the account hasn't used, then out again.
 */
function signInFromNewBrowser(string $email = 'taylor@example.com'): void
{
    test()->withUnencryptedCookies([])->post('/login', ['email' => $email, 'password' => 'password'])->assertRedirect('/dashboard');
    test()->post('/logout');
    test()->flushSession();
}

describe('security notices', function () {
    it('stops mailing an account about new devices after five in an hour, and logs every one', function () {
        foreach (range(1, 8) as $browser) {
            signInFromNewBrowser();
        }

        Notification::assertSentToTimes($this->user, NewDevice::class, 5);
        expect(SecurityEvent::query()->where('type', 'new_device')->count())->toBe(8);

        $this->travel(61)->minutes();
        signInFromNewBrowser();

        Notification::assertSentToTimes($this->user, NewDevice::class, 6);
    });

    it('counts each kind of notice on its own', function () {
        foreach (range(1, 6) as $browser) {
            signInFromNewBrowser();
        }

        PasswordChangedEvent::dispatch($this->user);

        Notification::assertSentToTimes($this->user, PasswordChanged::class, 1);
    });

    it('counts each account on its own', function () {
        $other = taylor(['email' => 'other@example.com']);

        foreach (range(1, 6) as $browser) {
            signInFromNewBrowser();
        }

        signInFromNewBrowser('other@example.com');

        Notification::assertSentToTimes($other, NewDevice::class, 1);
    });

    it('sends none to an address nobody has verified, which may be anyone\'s', function () {
        // Only signed in at all where registration signs new users in.
        revealTakenAddresses();
        $this->user->forceFill(['email_verified_at' => null])->save();

        signInFromNewBrowser();
        PasswordChangedEvent::dispatch($this->user->fresh());

        Notification::assertNothingSentTo($this->user);
        expect(SecurityEvent::query()->where('type', 'new_device')->count())->toBe(1);
    });

    // The reset link went to the address, so whoever finished the reset
    // reads its mailbox: the notice goes there whoever typed it at first.
    it('tells an address nobody had verified that its password was reset', function (bool $hidden) {
        $hidden || revealTakenAddresses();
        $this->user->forceFill(['email_verified_at' => null])->save();
        $token = Password::broker()->createToken($this->user);

        $this->post(route('password.update'), ['token' => $token, 'email' => 'taylor@example.com', 'password' => 'a-brand-new-long-password-1', 'password_confirmation' => 'a-brand-new-long-password-1'])
            ->assertSessionHasNoErrors();

        Notification::assertSentToTimes($this->user, PasswordChanged::class, 1);
        // Where registration hides who has an account, the reset verifies the address too.
        expect($this->user->fresh()->hasVerifiedEmail())->toBe($hidden);
    })->with(['where registration hides who has an account' => true, 'where it says when an address is taken' => false]);

    it('holds the newer notices to the same budget, with every event still logged', function () {
        $codes = Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

        foreach (range(1, 7) as $event) {
            RecoveryCodesGenerated::dispatch($this->user, $codes);
            AccountLockedEvent::dispatch($this->user, 'password');
        }

        Notification::assertSentToTimes($this->user, RecoveryCodesGeneratedNotice::class, 5);
        Notification::assertSentToTimes($this->user, AccountLocked::class, 5);
        expect(SecurityEvent::query()->where('type', 'recovery_codes_generated')->count())->toBe(7)
            ->and(SecurityEvent::query()->where('type', 'account_locked')->count())->toBe(7);
    });

    it('sends the newer notices to no address nobody has verified either', function () {
        $this->user->forceFill(['email_verified_at' => null])->save();
        $codes = Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

        RecoveryCodesGenerated::dispatch($this->user->fresh(), $codes);
        AccountLockedEvent::dispatch($this->user->fresh(), 'password');

        Notification::assertNothingSent();
        expect(SecurityEvent::query()->whereIn('type', ['recovery_codes_generated', 'account_locked'])->count())->toBe(2);
    });

    it('takes its numbers from the limits options', function () {
        config(['keyring.limits.notices' => 2, 'keyring.limits.notices_per' => '1d']);

        foreach (range(1, 4) as $browser) {
            signInFromNewBrowser();
        }

        $this->travel(23)->hours();
        signInFromNewBrowser();

        Notification::assertSentToTimes($this->user, NewDevice::class, 2);
    });
});

describe('email change requests', function () {
    function askToMoveTo(User $user, string $email): TestResponse
    {
        return test()->actingAs($user)->withAssurance(Assurance::AAL1)->postJson(route('keyring.email.store'), ['email' => $email]);
    }

    it('lets an account ask five times an hour, however the form limit resets', function () {
        foreach (range(1, 5) as $request) {
            askToMoveTo($this->user, "new{$request}@example.com")->assertOk();
            $this->travel(2)->minutes();
        }

        askToMoveTo($this->user, 'new6@example.com')
            ->assertStatus(429)
            ->assertJsonValidationErrors('email');

        Notification::assertSentTimes(EmailChangeNotice::class, 5);
        Notification::assertSentTimes(ConfirmEmailChange::class, 5);

        $this->travel(61)->minutes();

        askToMoveTo($this->user, 'new6@example.com')->assertOk();
    });

    it('refuses an account whose own address is unverified, which could never confirm the change', function () {
        // Only signed in at all where registration signs new users in.
        revealTakenAddresses();
        $this->user->forceFill(['email_verified_at' => null])->save();

        askToMoveTo($this->user->fresh(), 'someone@example.com')
            ->assertStatus(422)
            ->assertJsonPath('errors.email.0', __('keyring::keyring.verify_email_to_change'));

        Notification::assertNothingSent();
        expect(PendingChange::count())->toBe(0);
    });

    it('mails a typed address five times an hour at most, whichever accounts ask, without saying so', function () {
        $accounts = array_map(fn (int $n) => taylor(['email' => "account{$n}@example.com"]), range(1, 7));

        foreach ($accounts as $account) {
            $this->flushSession();
            askToMoveTo($account, 'Victim@Example.com')->assertOk();
        }

        Notification::assertSentTimes(ConfirmEmailChange::class, 5);
        Notification::assertSentTimes(EmailChangeNotice::class, 7);
    });
});
