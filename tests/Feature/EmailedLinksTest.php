<?php

declare(strict_types=1);

use App\Notifications\Keyring\ConfirmEmailChange;
use App\Notifications\Keyring\EmailChangeNotice;
use App\Notifications\Keyring\NewDevice;
use Illuminate\Auth\Events\Verified;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Str;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Features;
use Keyring\Http\Middleware\ValidatePostedSignature;
use Keyring\Models\Device;
use Keyring\Models\PendingChange;
use Keyring\Tests\Fixtures\User;

// An emailed link has to carry its token in its URL. The page it opens posts
// that token in the body, to a URL without it, so the request that acts
// doesn't write it to access logs and proxies a second time.
beforeEach(function () {
    Notification::fake();
    sendNotifications(['confirm_email_change', 'email_change_notice', 'new_device']);

    $this->user = taylor();
});

/**
 * Ask for an email change, and return the links that were emailed for it.
 *
 * @return array{confirm: string, revert: string, current: string}
 */
function emailedChangeLinks(): array
{
    test()->actingAs(test()->user)->withAssurance(Assurance::AAL1)->post(route('keyring.email.store'), ['email' => 'new@example.com'])->assertSessionHasNoErrors();
    test()->post('/logout');

    $links = [];

    Notification::assertSentTo(new AnonymousNotifiable, ConfirmEmailChange::class, function (ConfirmEmailChange $notice) use (&$links) {
        return (bool) ($links['confirm'] = $notice->url);
    });
    Notification::assertSentTo(new AnonymousNotifiable, EmailChangeNotice::class, function (EmailChangeNotice $notice) use (&$links) {
        return (bool) ([$links['revert'], $links['current']] = [$notice->revertUrl, $notice->confirmUrl]);
    });

    return $links;
}

/**
 * Sign in from a new browser, and return the "this wasn't me" link it was sent.
 */
function emailedReportLink(): string
{
    test()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
    test()->post('/logout');

    $url = null;

    Notification::assertSentTo(test()->user, NewDevice::class, function (NewDevice $notice) use (&$url) {
        return (bool) ($url = $notice->url);
    });

    return $url;
}

describe('an email change link', function () {
    beforeEach(function () {
        $this->links = emailedChangeLinks();
        $this->change = PendingChange::sole();
    });

    it('opens a page that posts the token in the body, to a URL without it', function (string $link, string $action) {
        $token = Str::afterLast($this->links[$link], '/');

        $props = $this->inertia()->get($this->links[$link])->assertOk()->json('props');

        expect($props['action'])->toBe($action)
            ->and($props['token'])->toBe($token)
            ->and($props['url'])->toBe(url("/email-changes/{$this->change->id}/{$action}"))
            ->and($props['url'])->not->toContain($token);
    })->with([
        'to confirm from the new address' => ['confirm', 'confirm'],
        'to confirm from the current address' => ['current', 'confirm'],
        'to undo' => ['revert', 'revert'],
    ]);

    it('confirms from both addresses with their tokens posted in the body', function () {
        foreach (['current' => 'email-change-confirmed', 'confirm' => 'email-changed'] as $link => $status) {
            $this->post(route('keyring.email.confirm.store', $this->change), ['token' => Str::afterLast($this->links[$link], '/')])
                ->assertRedirect(route('login'))
                ->assertSessionHas('status', $status);
        }

        expect($this->user->fresh()->email)->toBe('new@example.com');
    });

    it('undoes the change with its token posted in the body', function () {
        $this->post(route('keyring.email.revert.store', $this->change), ['token' => Str::afterLast($this->links['revert'], '/')])
            ->assertSessionHas('status', 'email-change-reverted');

        expect($this->change->fresh()->reverted_at)->not->toBeNull();
    });

    it('no longer acts on a token in the URL', function (string $link, string $action) {
        $token = Str::afterLast($this->links[$link], '/');

        // The link's own URL only ever shows the page.
        $this->post($this->links[$link])->assertMethodNotAllowed();

        // And the URL that acts reads no token from its query string.
        $this->post(route("keyring.email.{$action}.store", $this->change).'?token='.$token)->assertSessionHas('status', 'email-change-invalid');

        expect($this->change->fresh()->confirmed_at)->toBeNull()
            ->and($this->change->fresh()->reverted_at)->toBeNull();
    })->with([
        'to confirm' => ['confirm', 'confirm'],
        'to undo' => ['revert', 'revert'],
    ]);

    it('answers a missing or wrong token as an invalid link', function (array $body) {
        $this->post(route('keyring.email.confirm.store', $this->change), $body)->assertSessionHas('status', 'email-change-invalid');
        $this->post(route('keyring.email.revert.store', $this->change), $body)->assertSessionHas('status', 'email-change-invalid');

        expect($this->change->fresh()->isPending())->toBeTrue()
            ->and($this->change->fresh()->confirmed_at)->toBeNull();
    })->with([
        'no token' => [[]],
        'a wrong token' => [['token' => 'not-the-token']],
        'a token that is not text' => [['token' => ['x']]],
    ]);

    it('still works only once', function () {
        $token = Str::afterLast($this->links['revert'], '/');

        $this->post(route('keyring.email.revert.store', $this->change), ['token' => $token])->assertSessionHas('status', 'email-change-reverted');
        $this->post(route('keyring.email.revert.store', $this->change), ['token' => $token])->assertSessionHas('status', 'email-change-invalid');
    });

    it('still expires', function () {
        $this->travel(25)->hours();

        $this->post(route('keyring.email.confirm.store', $this->change), ['token' => Str::afterLast($this->links['confirm'], '/')])
            ->assertSessionHas('status', 'email-change-invalid');
    });
});

describe('a "this wasn\'t me" link', function () {
    beforeEach(function () {
        $this->url = emailedReportLink();

        parse_str((string) parse_url($this->url, PHP_URL_QUERY), $this->signed);
        $this->path = (string) parse_url($this->url, PHP_URL_PATH);
    });

    it('opens a page that posts the signature in the body, to a URL without it', function () {
        $props = $this->inertia()->get($this->path.'?'.http_build_query($this->signed))->assertOk()->json('props');

        expect($props['url'])->toBe($this->path)
            ->and($props['expires'])->toBe($this->signed['expires'])
            ->and($props['signature'])->toBe($this->signed['signature'])
            ->and(Device::sole()->isRevoked())->toBeFalse();
    });

    it('signs the device out when the signature is posted in the body', function () {
        $this->post($this->path, $this->signed)->assertRedirect(route('login'))->assertSessionHas('status', 'device-reported');

        expect(Device::sole()->isRevoked())->toBeTrue();
    });

    it('no longer acts on a signature in the URL', function () {
        $this->post($this->path.'?'.http_build_query($this->signed))->assertForbidden();

        expect(Device::sole()->isRevoked())->toBeFalse();
    });

    it('refuses a signature that is missing, wrong, or for another device', function (Closure $request) {
        [$path, $body] = $request($this->path, $this->signed);

        $this->post($path, $body)->assertForbidden();

        expect(Device::sole()->isRevoked())->toBeFalse();
    })->with([
        'nothing posted' => [fn (string $path, array $signed) => [$path, []]],
        'no signature' => [fn (string $path, array $signed) => [$path, ['expires' => $signed['expires']]]],
        'no expiry' => [fn (string $path, array $signed) => [$path, ['signature' => $signed['signature']]]],
        'a later expiry than was signed' => [fn (string $path, array $signed) => [$path, ['expires' => (string) ($signed['expires'] + 60), 'signature' => $signed['signature']]]],
        'a wrong signature' => [fn (string $path, array $signed) => [$path, ['expires' => $signed['expires'], 'signature' => str_repeat('0', 64)]]],
        'fields that are not text' => [fn (string $path, array $signed) => [$path, ['expires' => [$signed['expires']], 'signature' => [$signed['signature']]]]],
        'another device' => [fn (string $path, array $signed) => ['/devices/01HZZZZZZZZZZZZZZZZZZZZZZZ/report', $signed]],
    ]);

    it('still expires', function () {
        $this->travel(8)->days();

        $this->post($this->path, $this->signed)->assertForbidden();

        expect(Device::sole()->isRevoked())->toBeFalse();
    });
});

describe('an email verification link', function () {
    beforeEach(function () {
        // Opened by a signed-in user who hasn't verified, as there only is
        // where registration signs new users in.
        revealTakenAddresses();
        withFeatures(Features::all());
        Route::middleware(['web', 'auth'])->get('/dashboard', fn () => 'dashboard');

        $this->user = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password']);
        $this->actingAs($this->user)->post('/email/verification-notification')->assertSessionHas('status', 'verification-link-sent');

        Notification::assertSentTo($this->user, VerifyEmail::class, fn (VerifyEmail $notice) => (bool) ($this->url = $notice->toMail($this->user)->actionUrl));

        parse_str((string) parse_url($this->url, PHP_URL_QUERY), $this->signed);
        $this->path = (string) parse_url($this->url, PHP_URL_PATH);
        $this->link = $this->path.'?'.http_build_query($this->signed);
    });

    it('verifies nothing when it is only opened', function () {
        Event::fake([Verified::class]);

        $props = $this->inertia()->get($this->link)
            ->assertOk()
            ->assertJsonPath('component', 'auth/email-verification')
            ->assertHeader('Referrer-Policy', 'no-referrer')
            ->json('props');

        expect($props)->toMatchArray(['email' => 'abigail@example.com', 'url' => $this->path, 'expires' => $this->signed['expires'], 'signature' => $this->signed['signature']])
            ->and($this->user->fresh()->hasVerifiedEmail())->toBeFalse();

        Event::assertNotDispatched(Verified::class);
    });

    it('verifies the address when the page posts the signature, and says so as Laravel does', function () {
        Event::fake([Verified::class]);

        $this->post($this->path, $this->signed)->assertRedirect('/dashboard?verified=1');

        expect($this->user->fresh()->hasVerifiedEmail())->toBeTrue();
        Event::assertDispatched(Verified::class, fn (Verified $event) => $event->user->is($this->user));
    });

    it('works for the link Laravel\'s own notification builds', function () {
        // An app that set its own link, signed as Keyring's route checks it.
        $url = URL::temporarySignedRoute('verification.verify', now()->addHour(), ['id' => $this->user->id, 'hash' => sha1('abigail@example.com')], absolute: false);

        $this->inertia()->get($url)->assertOk()->assertJsonPath('component', 'auth/email-verification');
        $this->flushHeaders();

        postSignedLink($url)->assertRedirect('/dashboard?verified=1');
        expect($this->user->fresh()->hasVerifiedEmail())->toBeTrue();
    });

    it('no longer acts on a signature in the URL', function () {
        $this->post($this->link)->assertForbidden();

        expect($this->user->fresh()->hasVerifiedEmail())->toBeFalse();
    });

    it('refuses a signature that is missing, wrong or out of date', function (Closure $body, int $minutes) {
        $this->travel($minutes)->minutes();
        $this->actingAs($this->user);

        $this->post($this->path, $body($this->signed))->assertForbidden();

        expect($this->user->fresh()->hasVerifiedEmail())->toBeFalse();
    })->with([
        'nothing posted' => [fn (array $signed) => [], 0],
        'a wrong signature' => [fn (array $signed) => [...$signed, 'signature' => str_repeat('0', 64)], 0],
        'a link that ran out' => [fn (array $signed) => $signed, 61],
    ]);

    it('is only good for the account it was sent to, signed in', function () {
        $other = User::create(['name' => 'Taylor Too', 'email' => 'other@example.com', 'password' => 'password']);

        $this->post('/logout');
        $this->post($this->path, $this->signed)->assertRedirect(route('login'));
        $this->get($this->link)->assertRedirect(route('login'));

        $this->flushSession()->actingAs($other);
        $this->post($this->path, $this->signed)->assertForbidden();
        $this->get($this->link)->assertForbidden();

        expect($this->user->fresh()->hasVerifiedEmail())->toBeFalse()
            ->and($other->fresh()->hasVerifiedEmail())->toBeFalse();
    });

    it('stops working once the address it was sent to is no longer the account\'s', function () {
        Keyring::withoutProtection(fn () => $this->user->forceFill(['email' => 'moved@example.com'])->save(), 'test');

        $this->actingAs($this->user->fresh())->post($this->path, $this->signed)->assertForbidden();

        expect($this->user->fresh()->hasVerifiedEmail())->toBeFalse();
    });

    it('sends someone already verified on, without a page or a second event', function () {
        $this->user->markEmailAsVerified();
        Event::fake([Verified::class]);

        $this->get($this->link)->assertRedirect('/dashboard');
        $this->post($this->path, $this->signed)->assertRedirect('/dashboard?verified=1');

        Event::assertNotDispatched(Verified::class);
    });
});

it('keeps the rate limit and the CSRF check on the routes that act', function (string $name) {
    $middleware = Route::getRoutes()->getByName($name)->gatherMiddleware();

    expect($middleware)->toContain('throttle:keyring')->toContain('web')
        ->and(app('router')->getMiddlewareGroups()['web'])->toContain(PreventRequestForgery::class);
})->with(['keyring.email.confirm.store', 'keyring.email.revert.store', 'keyring.devices.report.store', 'verification.verify.store']);

it('checks the signature on both the link and the form it posts', function (string $link) {
    expect(Route::getRoutes()->getByName($link)->gatherMiddleware())->toContain('keyring.signed:relative')
        ->and(Route::getRoutes()->getByName($link.'.store')->gatherMiddleware())->toContain(ValidatePostedSignature::class);
})->with(['keyring.devices.report', 'verification.verify']);

it('changes nothing on a GET, on any of its routes', function () {
    $acting = collect(Route::getRoutes()->getRoutes())
        ->filter(fn ($route) => in_array('GET', $route->methods(), true) && str_starts_with((string) $route->getActionName(), 'Keyring\\'))
        ->map(fn ($route) => class_basename($route->getActionName()))
        ->values()
        ->all();

    // Every one of these renders a page or answers with what's there.
    expect($acting)->toEqualCanonicalizing([
        'RegisteredUserController@create', 'PasswordResetController@create', 'PasswordResetController@edit',
        'AuthenticatedSessionController@create', 'AuthenticatedSessionController@options',
        'ChallengeController@show', 'ChallengeController@show',
        'DeviceController@index', 'DeviceController@page', 'SessionController@index',
        'EmailChangeController@show', 'EmailChangeController@page', 'EmailChangeController@page',
        'EmailVerificationController@notice', 'EmailVerificationController@page',
    ]);
});

it('has no token left in the URL of any route that acts on an emailed link', function (string $name) {
    expect(Route::getRoutes()->getByName($name)->parameterNames())->not->toContain('token');
})->with(['keyring.email.confirm.store', 'keyring.email.revert.store', 'keyring.devices.report.store', 'password.update']);

it('has no signature in the URL of a route that acts on a signed link', function (string $name) {
    expect(Route::getRoutes()->getByName($name)->gatherMiddleware())->not->toContain('keyring.signed:relative')->not->toContain('signed');
})->with(['keyring.devices.report.store', 'verification.verify.store']);
