<?php

use App\Notifications\Keyring\ConfirmEmailChange;
use App\Notifications\Keyring\EmailChangeNotice;
use App\Notifications\Keyring\NewDevice;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Keyring\Enums\Assurance;
use Keyring\Http\Middleware\ValidatePostedSignature;
use Keyring\Models\Device;
use Keyring\Models\PendingChange;

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

it('keeps the rate limit and the CSRF check on the routes that act', function (string $name) {
    $middleware = Route::getRoutes()->getByName($name)->gatherMiddleware();

    expect($middleware)->toContain('throttle:keyring')->toContain('web')
        ->and(app('router')->getMiddlewareGroups()['web'])->toContain(PreventRequestForgery::class);
})->with(['keyring.email.confirm.store', 'keyring.email.revert.store', 'keyring.devices.report.store']);

it('checks the signature on both the link and the form it posts', function () {
    expect(Route::getRoutes()->getByName('keyring.devices.report')->gatherMiddleware())->toContain('signed:relative')
        ->and(Route::getRoutes()->getByName('keyring.devices.report.store')->gatherMiddleware())->toContain(ValidatePostedSignature::class);
});

it('has no token left in the URL of any route that acts on an emailed link', function (string $name) {
    expect(Route::getRoutes()->getByName($name)->parameterNames())->not->toContain('token');
})->with(['keyring.email.confirm.store', 'keyring.email.revert.store', 'keyring.devices.report.store', 'password.update']);
