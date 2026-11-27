<?php

declare(strict_types=1);

// Its own namespace, so its helpers can't collide with another file's.

namespace Keyring\Tests\Feature\Detours;

use Illuminate\Auth\GenericUser;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Uri;
use Illuminate\Testing\TestResponse;
use Keyring\Contracts\Responses\ConfirmationRequiredResponse;
use Keyring\Contracts\Responses\EnrollmentRequiredResponse;
use Keyring\Contracts\Responses\PasswordChangeRequiredResponse;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Http\Middleware\RequireAssurance;
use Keyring\Login\Detours;
use Keyring\Login\Requirement;
use Keyring\Login\StepUp;
use Keyring\Models\Authenticator;
use Keyring\Notifications\VerificationCode;
use Keyring\Sessions\RegisteredSession;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\Tests\Fixtures\SingleSignOn as SingleSignOnFixture;
use Keyring\Tests\Fixtures\User;

// Where a user was going when Keyring sent them to enroll or to choose a new
// password, handed back once they have.

const NAVIGATE = ['Sec-Fetch-Mode' => 'navigate', 'Sec-Fetch-Dest' => 'document'];

beforeEach(function () {
    Route::middleware(['web', 'keyring.enrolled'])->group(function () {
        Route::get('/invoices/{invoice}', fn (string $invoice) => "invoice {$invoice}");
        Route::post('/invoices/{invoice}', fn (string $invoice) => "paid {$invoice}");
        Route::get('/invoices/{invoice}/logo.png', fn () => 'png');
        Route::get('/settings/security', fn () => 'security');
    });

    Route::middleware(['web', 'auth', 'keyring:aal2'])->get('/billing', fn () => 'billing');
    Route::middleware(['web', 'auth', 'keyring:aal3'])->get('/vault', fn () => 'vault');

    Route::middleware(['web', 'auth'])->group(function () {
        Route::get('/home', fn () => 'home');
        Route::get('/settings/password', fn () => 'choose a new password');
    });

    // A page that asks for something the account has nothing for, the way
    // an app can start a confirm itself.
    Route::middleware(['web', 'auth'])->get('/keys-only', function (Request $request) {
        app(StepUp::class)->begin($request, Requirement::aal2()->deviceBound());

        return Keyring::response(ConfirmationRequiredResponse::class)->toResponse($request);
    });

    // Somewhere for a test to ask what's saved, as a page would.
    Route::middleware('web')->get('/detour/{key}', fn (Request $request, string $key) => app(Detours::class)->pull($request, $key === 'password' ? Detours::PASSWORD_CHANGE : Detours::ENROLLMENT) ?? 'nothing');

    config(['keyring.enrollment_url' => '/settings/security', 'keyring.password_change_url' => '/settings/password']);

    $this->user = taylor();
});

function signIn(string $email = 'taylor@example.com'): void
{
    test()->post('/login', ['email' => $email, 'password' => 'password'])->assertSessionHasNoErrors();
}

function addAuthenticatorApp(): array
{
    $secret = test()->postJson(route('keyring.authenticators.store', 'totp'))->assertOk()->json('enrollment.secret');

    return test()->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk()->json();
}

/**
 * Add a passkey, one that stays on its device unless it's $synced.
 */
function addPasskey(bool $synced = false): array
{
    $options = test()->postJson(route('keyring.authenticators.store', 'passkey'))->assertOk()->json('enrollment.options');

    return test()->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => new VirtualAuthenticator(synced: $synced)->register($options)])->assertOk()->json();
}

/**
 * Add an emailed code, which is a step at sign in but not a second factor.
 */
function addEmailCode(): array
{
    test()->postJson(route('keyring.authenticators.store', 'email-code'))->assertOk();
    $code = Notification::sent(test()->user, VerificationCode::class)->last()->code;

    return test()->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => $code])->assertOk()->json();
}

/**
 * What keyring.enrolled saves a page with: the account must meet AAL2
 * without its recovery codes.
 *
 * @return array<string, mixed>
 */
function needingAal2(): array
{
    return Requirement::named('aal2')->toArray();
}

/**
 * @return array{url: string, user: array{type: string, id: string}, at: int}
 */
function savedFor(Model $user, string $url = 'http://localhost/invoices/42', ?int $at = null): array
{
    return ['url' => $url, 'user' => ['type' => RegisteredSession::typeOf($user), 'id' => (string) $user->getKey()], 'at' => $at ?? now()->getTimestamp()];
}

describe('enrolling', function () {
    it('hands back the page keyring.enrolled stopped them on', function () {
        signIn();

        $this->get('/invoices/42', NAVIGATE)->assertRedirect('/settings/security');

        expect(session(Detours::ENROLLMENT))->toBe([...savedFor($this->user), 'requirement' => needingAal2()])
            ->and(addAuthenticatorApp())->toMatchArray(['status' => 'authenticator-added', 'continue' => 'http://localhost/invoices/42'])
            ->and(session()->has(Detours::ENROLLMENT))->toBeFalse();
    });

    it('keeps the query string', function () {
        signIn();

        $this->get('/invoices/42?tab=lines', NAVIGATE)->assertRedirect('/settings/security');

        expect(addAuthenticatorApp()['continue'])->toBe('http://localhost/invoices/42?tab=lines');
    });

    it('flashes it with the rest of the result for a page', function () {
        signIn();
        $this->get('/invoices/42', NAVIGATE);

        $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');
        $this->from('/settings/security')
            ->post(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])
            ->assertRedirect('/settings/security');

        expect(Keyring::result('continue'))->toBe('http://localhost/invoices/42')
            ->and(Keyring::result('recoveryCodes'))->toHaveCount(8);
    });

    it('hands back the page step-up stopped them on when the account could not reach the level', function () {
        signIn();

        $this->get('/billing', NAVIGATE)->assertRedirect('/settings/security');

        expect(addAuthenticatorApp()['continue'])->toBe('http://localhost/billing');
    });

    it('hands back the page a confirm was for when there was nothing to confirm with', function () {
        signIn();

        $this->get('/keys-only', NAVIGATE)->assertRedirect(route('keyring.confirm.challenge'));
        $this->get(route('keyring.confirm.challenge'), NAVIGATE)->assertRedirect('/settings/security');

        expect(session(Detours::ENROLLMENT)['requirement'])->toBe(Requirement::aal2()->deviceBound()->toArray())
            ->and(addPasskey()['continue'])->toBe('http://localhost/keys-only');
    });

    it('keeps the page a confirm was for until the account has what the confirm asks', function () {
        signIn();

        $this->get('/keys-only', NAVIGATE)->assertRedirect(route('keyring.confirm.challenge'));
        $this->get(route('keyring.confirm.challenge'), NAVIGATE)->assertRedirect('/settings/security');

        // Neither an authenticator app nor a passkey that syncs is bound to
        // a device.
        expect(addAuthenticatorApp())->not->toHaveKey('continue')
            ->and(addPasskey(synced: true))->not->toHaveKey('continue')
            ->and(session(Detours::ENROLLMENT)['url'])->toBe('http://localhost/keys-only')
            ->and(addPasskey()['continue'])->toBe('http://localhost/keys-only')
            ->and(session()->has(Detours::ENROLLMENT))->toBeFalse();
    });

    it('hands back the page keyring.enrolled stopped them on for a passkey', function () {
        signIn();

        $this->get('/invoices/42', NAVIGATE)->assertRedirect('/settings/security');

        expect(addPasskey()['continue'])->toBe('http://localhost/invoices/42');
    });

    it('keeps the page for a second factor when they add an emailed code, which isn\'t one', function () {
        Notification::fake();
        Keyring::factors([Password::class, WebAuthn::passkeys(), Totp::class, RecoveryCodes::class, EmailCode::asExtraStep()]);
        signIn();

        $this->get('/invoices/42', NAVIGATE)->assertRedirect('/settings/security');

        expect(addEmailCode())->toMatchArray(['status' => 'authenticator-added'])->not->toHaveKey('continue')
            ->and(session(Detours::ENROLLMENT))->toMatchArray(['url' => 'http://localhost/invoices/42', 'requirement' => needingAal2()]);

        // Still a page keyring.enrolled sends them back from.
        $this->get('/invoices/42', NAVIGATE)->assertRedirect('/settings/security');

        expect(addAuthenticatorApp()['continue'])->toBe('http://localhost/invoices/42')
            ->and(session()->has(Detours::ENROLLMENT))->toBeFalse();
    });

    it('keeps the page step-up stopped them on until the account can reach the level', function () {
        signIn();

        $this->get('/vault', NAVIGATE)->assertRedirect('/settings/security');

        // A code from an app is never AAL3.
        expect(addAuthenticatorApp())->not->toHaveKey('continue')
            ->and(session(Detours::ENROLLMENT))->toMatchArray(['url' => 'http://localhost/vault', 'requirement' => Requirement::aal3()->toArray()]);
    });

    it('keeps the page until the account can reach a level the route asks for after keyring.enrolled', function (string $assurance) {
        // As the installer sets it up: keyring.enrolled in the web group,
        // so it stops the request before the route's own level is asked.
        app('router')->aliasMiddleware('assurance', RequireAssurance::class);
        Route::middleware(['web', 'keyring.enrolled', 'auth', $assurance])->get('/vault/stacked', fn () => 'vault');
        signIn();

        $this->get('/vault/stacked', NAVIGATE)->assertRedirect('/settings/security');

        expect(session(Detours::ENROLLMENT)['requirement'])->toBe(Requirement::named('aal2')->atLeast(Requirement::aal3())->toArray())
            ->and(addAuthenticatorApp())->not->toHaveKey('continue')
            ->and(session(Detours::ENROLLMENT)['url'])->toBe('http://localhost/vault/stacked');

        // keyring.enrolled lets them through now, and the level sends them
        // back to enroll for it, with the page still saved.
        $this->get('/vault/stacked', NAVIGATE)->assertRedirect('/settings/security');

        expect(session(Detours::ENROLLMENT)['requirement'])->toBe(Requirement::aal3()->toArray());
    })->with(['keyring:aal3', 'assurance:aal3', RequireAssurance::class.':aal3']);

    it('saves the level keyring.enrolled asks for alone when the route asks for nothing more', function () {
        Route::middleware(['web', 'keyring.enrolled', 'auth', 'keyring'])->get('/billing/stacked', fn () => 'billing');
        signIn();

        $this->get('/billing/stacked', NAVIGATE)->assertRedirect('/settings/security');

        expect(session(Detours::ENROLLMENT)['requirement'])->toBe(needingAal2())
            ->and(addAuthenticatorApp()['continue'])->toBe('http://localhost/billing/stacked');
    });

    it('hands back a page saved without a requirement on the next sign-in method, as before', function () {
        // As one saved before Keyring kept the requirement, or by an app
        // calling remember() without one.
        Notification::fake();
        Keyring::factors([Password::class, WebAuthn::passkeys(), Totp::class, RecoveryCodes::class, EmailCode::asExtraStep()]);
        signIn();
        $this->withSession([Detours::ENROLLMENT => savedFor($this->user)]);

        expect(addEmailCode()['continue'])->toBe('http://localhost/invoices/42')
            ->and(session()->has(Detours::ENROLLMENT))->toBeFalse();
    });

    it('saves nothing from a visit to the confirm page of their own, whatever url.intended holds', function () {
        $this->user->forceFill(['password' => null])->saveQuietly();
        $this->actingAs($this->user)->withSession(['url.intended' => 'http://localhost/account']);

        $this->get(route('keyring.confirm.challenge'), NAVIGATE)->assertRedirect('/settings/security');

        expect(session()->has(Detours::ENROLLMENT))->toBeFalse();
    });

    it('does not carry a page someone else was sent to sign in for over the confirm page', function () {
        // A guest was stopped on a page and sent to sign in, which leaves it
        // in url.intended. The app then signs in someone else itself.
        $this->get('/home', NAVIGATE)->assertRedirect('/login');
        expect(session('url.intended'))->toBe('http://localhost/home');

        $sso = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => null, 'email_verified_at' => now()]);
        Route::middleware('web')->get('/sso', function () use ($sso) {
            Auth::login($sso);

            return 'ok';
        });
        $this->get('/sso')->assertOk();

        $this->get(route('keyring.confirm.challenge'), NAVIGATE)->assertRedirect('/settings/security');

        expect(session()->has(Detours::ENROLLMENT))->toBeFalse();
    });

    it('saves nothing from the confirm page when the page it was for is on another site', function (string $url) {
        signIn();
        $this->get('/keys-only', NAVIGATE);
        session()->put('url.intended', $url);

        $this->get(route('keyring.confirm.challenge'), NAVIGATE)->assertRedirect('/settings/security');

        expect(session()->has(Detours::ENROLLMENT))->toBeFalse();
    })->with(['http://localhost.evil.test/account', '//evil.test/account', 'https://localhost/account', 'http://localhost@evil.test/']);

    it('saves nothing from the confirm page when the page it was for is the enrollment page', function () {
        signIn();
        $this->get('/invoices/42', NAVIGATE);
        $this->get('/keys-only', NAVIGATE);
        session()->put('url.intended', 'http://localhost/settings/security?tab=keys');

        $this->get(route('keyring.confirm.challenge'), NAVIGATE)->assertRedirect('/settings/security');

        expect(session(Detours::ENROLLMENT)['url'])->toBe('http://localhost/invoices/42');
    });

    it('does not save the enrollment page itself, or replace what was saved with it', function () {
        signIn();
        $this->get('/invoices/42', NAVIGATE);
        config(['keyring.enrollment_url' => '/billing']);

        $this->get('/billing', NAVIGATE)->assertForbidden();

        expect(session(Detours::ENROLLMENT)['url'])->toBe('http://localhost/invoices/42');
    });

    it('hands nothing back for new recovery codes, and keeps it for the factor they still need', function () {
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();
        $this->actingAs($this->user)->withAssurance(Assurance::AAL2)->withSession([Detours::ENROLLMENT => savedFor($this->user)]);

        $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();
        $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk()->assertJsonMissingPath('continue');

        expect(session(Detours::ENROLLMENT)['url'])->toBe('http://localhost/invoices/42');
    });

    it('keeps it through a wrong code, for the one that works', function () {
        signIn();
        $this->get('/invoices/42', NAVIGATE);

        $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');
        $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => '000000'])->assertUnprocessable();

        expect(session()->has(Detours::ENROLLMENT))->toBeTrue();

        $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])
            ->assertOk()
            ->assertJsonPath('continue', 'http://localhost/invoices/42');
    });

    it('leaves it out when there is nothing to carry on to', function () {
        signIn();

        expect(addAuthenticatorApp())->not->toHaveKey('continue');
    });

    it('saves it for an app\'s own response too', function () {
        Keyring::respondWith(EnrollmentRequiredResponse::class, fn () => new class implements EnrollmentRequiredResponse
        {
            public function toResponse($request)
            {
                return redirect('/welcome/second-factor');
            }
        });
        signIn();

        $this->get('/invoices/42', NAVIGATE)->assertRedirect('/welcome/second-factor');

        expect(addAuthenticatorApp()['continue'])->toBe('http://localhost/invoices/42');
    });

    it('saves an inertia visit', function () {
        signIn();

        $this->get('/invoices/42', ['X-Inertia' => 'true', 'Sec-Fetch-Mode' => 'cors'])->assertRedirect('/settings/security');

        expect(session(Detours::ENROLLMENT)['url'])->toBe('http://localhost/invoices/42');
    });

    it('saves an inertia visit that also accepts json', function () {
        signIn();

        $this->get('/invoices/42', ['X-Inertia' => 'true', 'Accept' => 'text/html, application/json'])->assertRedirect('/settings/security');

        expect(session(Detours::ENROLLMENT)['url'])->toBe('http://localhost/invoices/42');
    });

    it('saves nothing for a HEAD request', function () {
        signIn();

        $this->call('HEAD', '/invoices/42', server: ['HTTP_SEC_FETCH_MODE' => 'navigate', 'HTTP_SEC_FETCH_DEST' => 'document'])->assertRedirect('/settings/security');

        expect(session()->has(Detours::ENROLLMENT))->toBeFalse();
    });

    it('saves a navigation from a browser that sends no Sec-Fetch-Dest', function () {
        signIn();

        $this->get('/invoices/42', ['Sec-Fetch-Mode' => 'navigate'])->assertRedirect('/settings/security');

        expect(session(Detours::ENROLLMENT)['url'])->toBe('http://localhost/invoices/42');
    });

    it('neither saves nor replaces anything for a request that is not a navigation', function (array $headers) {
        signIn();
        $this->get('/invoices/42', NAVIGATE);

        $this->get('/invoices/7/logo.png', $headers);

        expect(session(Detours::ENROLLMENT)['url'])->toBe('http://localhost/invoices/42');

        session()->forget(Detours::ENROLLMENT);
        $this->get('/invoices/7/logo.png', $headers);

        expect(session()->has(Detours::ENROLLMENT))->toBeFalse();
    })->with([
        'no Sec-Fetch-Mode' => [[]],
        'cors' => [['Sec-Fetch-Mode' => 'cors', 'Sec-Fetch-Dest' => 'empty', 'Accept' => '*/*']],
        'no-cors' => [['Sec-Fetch-Mode' => 'no-cors', 'Sec-Fetch-Dest' => 'image']],
        'an image' => [['Sec-Fetch-Mode' => 'navigate', 'Sec-Fetch-Dest' => 'image']],
        'a frame' => [['Sec-Fetch-Mode' => 'navigate', 'Sec-Fetch-Dest' => 'iframe']],
        'an inertia prefetch' => [['X-Inertia' => 'true', 'Purpose' => 'prefetch']],
        'an inertia partial reload' => [['X-Inertia' => 'true', 'X-Inertia-Partial-Component' => 'Invoices/Show']],
        'an inertia partial reload of data' => [['X-Inertia' => 'true', 'X-Inertia-Partial-Data' => 'lines']],
        'json' => [['Accept' => 'application/json', 'Sec-Fetch-Mode' => 'navigate']],
        'a speculation rules prefetch' => [[...NAVIGATE, 'Sec-Purpose' => 'prefetch']],
        'a prerender' => [[...NAVIGATE, 'Sec-Purpose' => 'prefetch;prerender']],
        'a prefetch with Purpose' => [[...NAVIGATE, 'Purpose' => 'prefetch']],
        'an inertia visit the browser prefetches' => [['X-Inertia' => 'true', 'Sec-Purpose' => 'prefetch']],
    ]);

    it('neither saves nor replaces anything for a form post', function () {
        signIn();
        $this->get('/invoices/42', NAVIGATE);

        $this->post('/invoices/7', [], NAVIGATE)->assertRedirect('/settings/security');

        expect(session(Detours::ENROLLMENT)['url'])->toBe('http://localhost/invoices/42');
    });

    it('does not hand one user\'s page to another who signs in with keyring', function () {
        $this->withSession([Detours::ENROLLMENT => savedFor($this->user), Detours::PASSWORD_CHANGE => savedFor($this->user)]);
        User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);

        signIn('abigail@example.com');

        expect(session()->has(Detours::ENROLLMENT))->toBeFalse()
            ->and(session()->has(Detours::PASSWORD_CHANGE))->toBeFalse()
            ->and(addAuthenticatorApp())->not->toHaveKey('continue');
    });

    it('does not hand one user\'s page to another the app signs in itself', function () {
        $abigail = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        Route::middleware('web')->get('/impersonate', function () use ($abigail) {
            Auth::login($abigail);

            return 'ok';
        });

        $this->withSession([Detours::ENROLLMENT => savedFor($this->user)]);
        $this->get('/impersonate')->assertOk();

        expect($this->get('/detour/enrollment')->assertOk()->getContent())->toBe('nothing')
            ->and(Auth::id())->toBe($abigail->getKey())
            ->and(session()->has(Detours::ENROLLMENT))->toBeFalse();
    });

    it('does not hand a page to an account of another model with the same id', function () {
        $staff = staff();
        $this->actingAs($staff)->withSession([Detours::ENROLLMENT => savedFor($this->user)]);

        expect($staff->getKey())->toBe($this->user->getKey())
            ->and($this->get('/detour/enrollment')->getContent())->toBe('nothing');
    });

    it('forgets a page saved over an hour ago', function () {
        signIn();
        $this->get('/invoices/42', NAVIGATE);

        $this->travel(Detours::LIFETIME + 1)->seconds();

        expect($this->get('/detour/enrollment')->assertOk()->getContent())->toBe('nothing')
            ->and(session()->has(Detours::ENROLLMENT))->toBeFalse();
    });

    it('hands back a page saved just under an hour ago', function () {
        signIn();
        $this->get('/invoices/42', NAVIGATE);

        $this->travel(Detours::LIFETIME)->seconds();
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        expect($this->get('/detour/enrollment')->getContent())->toBe('http://localhost/invoices/42');
    });
});

describe('a saved page that has been tampered with', function () {
    beforeEach(fn () => $this->actingAs($this->user));

    it('is refused when it points at another site', function (string $url) {
        $this->withSession([Detours::ENROLLMENT => savedFor($this->user, $url)]);

        expect($this->get('/detour/enrollment')->getContent())->toBe('nothing')
            ->and(session()->has(Detours::ENROLLMENT))->toBeFalse();
    })->with([
        'http://localhost.evil.test/invoices/42',
        'https://app.example.com.evil.test/',
        '//evil.test/invoices/42',
        'https://localhost/invoices/42',
        'http://localhost@evil.test/',
        'http://localhost:8080/invoices/42',
        'javascript:alert(1)',
        '/invoices/42',
    ]);

    it('is refused when it isn\'t shaped like one', function (mixed $saved) {
        $this->withSession([Detours::ENROLLMENT => $saved]);

        expect($this->get('/detour/enrollment')->getContent())->toBe('nothing')
            ->and(session()->has(Detours::ENROLLMENT))->toBeFalse();
    })->with([
        'a bare url' => ['http://localhost/invoices/42'],
        'no user' => [['url' => 'http://localhost/invoices/42', 'at' => time()]],
        'no time' => [['url' => 'http://localhost/invoices/42', 'user' => ['type' => 'testing:users', 'id' => '1']]],
        'a url that isn\'t text' => [['url' => ['http://localhost/'], 'user' => ['type' => 'testing:users', 'id' => '1'], 'at' => time()]],
    ]);

    it('is refused when its requirement isn\'t one', function (mixed $requirement) {
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        $this->withSession([Detours::ENROLLMENT => [...savedFor($this->user), 'requirement' => $requirement]]);

        expect($this->get('/detour/enrollment')->getContent())->toBe('nothing')
            ->and(session()->has(Detours::ENROLLMENT))->toBeFalse();
    })->with([
        'null' => [null],
        'a name' => ['aal2'],
        'empty' => [[]],
        'an unknown category' => [[...Requirement::aal2()->toArray(), 'categories' => ['telepathy']]],
    ]);

    it('is refused when saved in the future', function () {
        $this->withSession([Detours::ENROLLMENT => savedFor($this->user, at: now()->addMinute()->getTimestamp())]);

        expect($this->get('/detour/enrollment')->getContent())->toBe('nothing');
    });

    it('is still handed back when it is genuine', function () {
        $this->withSession([Detours::ENROLLMENT => savedFor($this->user)]);

        expect($this->get('/detour/enrollment')->getContent())->toBe('http://localhost/invoices/42');
    });

    it('hands back nothing to a guest, and forgets it', function () {
        Auth::logout();
        $this->withSession([Detours::ENROLLMENT => savedFor($this->user)]);

        expect($this->get('/detour/enrollment')->getContent())->toBe('nothing')
            ->and(session()->has(Detours::ENROLLMENT))->toBeFalse();
    });
});

describe('a saved page with a requirement', function () {
    beforeEach(fn () => $this->actingAs($this->user));

    it('is kept, not handed back, while the account can\'t meet it', function () {
        $this->withSession([Detours::ENROLLMENT => [...savedFor($this->user), 'requirement' => needingAal2()]]);

        expect($this->get('/detour/enrollment')->getContent())->toBe('nothing')
            ->and(session(Detours::ENROLLMENT)['url'])->toBe('http://localhost/invoices/42');

        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        expect($this->get('/detour/enrollment')->getContent())->toBe('http://localhost/invoices/42')
            ->and(session()->has(Detours::ENROLLMENT))->toBeFalse();
    });

    it('keeps the hour it was saved with while it waits', function () {
        $this->withSession([Detours::ENROLLMENT => [...savedFor($this->user), 'requirement' => needingAal2()]]);

        $this->travel(30)->minutes();

        expect($this->get('/detour/enrollment')->getContent())->toBe('nothing')
            ->and(session()->has(Detours::ENROLLMENT))->toBeTrue();

        $this->travel(31)->minutes();
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        expect($this->get('/detour/enrollment')->getContent())->toBe('nothing')
            ->and(session()->has(Detours::ENROLLMENT))->toBeFalse();
    });

    it('is forgotten, not kept, when it was saved for someone else', function () {
        $abigail = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        $this->withSession([Detours::ENROLLMENT => [...savedFor($abigail), 'requirement' => needingAal2()]]);

        expect($this->get('/detour/enrollment')->getContent())->toBe('nothing')
            ->and(session()->has(Detours::ENROLLMENT))->toBeFalse();
    });

    it('is refused for a user that isn\'t a model, with no authenticators to meet it', function () {
        // Asked directly: Keyring's session middleware signs such a user out.
        $user = new GenericUser(['id' => 1]);
        Keyring::guard()->setUser($user);
        $request = Request::create('http://localhost/settings/security');
        $request->setLaravelSession($session = app('session.store'));
        $session->put(Detours::ENROLLMENT, [
            'url' => 'http://localhost/invoices/42',
            'user' => ['type' => RegisteredSession::typeOf($user), 'id' => '1'],
            'at' => now()->getTimestamp(),
            'requirement' => needingAal2(),
        ]);

        expect(app(Detours::class)->pull($request, Detours::ENROLLMENT))->toBeNull()
            ->and($session->has(Detours::ENROLLMENT))->toBeFalse();
    });

    it('isn\'t met with a sign-in method the confirm page can\'t ask for, as step-up wouldn\'t take it', function () {
        Keyring::factors([Password::class, Totp::class, SingleSignOnFixture::class]);
        $this->user->forceFill(['password' => null])->saveQuietly();
        $this->withSession([Detours::ENROLLMENT => [...savedFor($this->user), 'requirement' => Requirement::aal1()->toArray()]]);

        // Signing in with it would meet the requirement, but a confirm can't ask for it.
        expect($this->user->keyring->canMeet(Requirement::aal1()))->toBeTrue()
            ->and($this->get('/detour/enrollment')->getContent())->toBe('nothing')
            ->and(session()->has(Detours::ENROLLMENT))->toBeTrue();

        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        expect($this->get('/detour/enrollment')->getContent())->toBe('http://localhost/invoices/42');
    });

    it('isn\'t met with recovery codes', function () {
        Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();
        $this->withSession([Detours::ENROLLMENT => [...savedFor($this->user), 'requirement' => Requirement::aal1()->including(Category::Possession)->toArray()]]);

        expect($this->get('/detour/enrollment')->getContent())->toBe('nothing')
            ->and(session()->has(Detours::ENROLLMENT))->toBeTrue();
    });
});

it('hands back nothing without a session', function () {
    expect(app(Detours::class)->pull(Request::create('/'), Detours::ENROLLMENT))->toBeNull();
});

describe('a held password change', function () {
    beforeEach(function () {
        signIn();
        Keyring::requirePasswordChange($this->user);
    });

    function changePassword(bool $json = true): TestResponse
    {
        $fields = ['current_password' => 'password', 'password' => 'a much longer passphrase', 'password_confirmation' => 'a much longer passphrase'];

        return $json
            ? test()->putJson(route('user-password.update'), $fields)
            : test()->from('/settings/password')->put(route('user-password.update'), $fields);
    }

    it('carries on to the page the hold stopped them on', function () {
        $this->get('/home', NAVIGATE)->assertRedirect('/settings/password');

        expect(session(Detours::PASSWORD_CHANGE))->toBe(savedFor($this->user, 'http://localhost/home'));

        changePassword(json: false)->assertRedirect('http://localhost/home')->assertSessionHas('status', 'password-updated');

        expect(session()->has(Detours::PASSWORD_CHANGE))->toBeFalse();
    });

    it('tells json callers where to carry on to', function () {
        $this->get('/home', NAVIGATE);

        changePassword()->assertOk()->assertJson(['status' => 'password-updated', 'redirect' => 'http://localhost/home']);
    });

    it('keeps it through a wrong current password, for the try that works', function () {
        $this->get('/home', NAVIGATE);

        $this->putJson(route('user-password.update'), ['current_password' => 'wrong', 'password' => 'a much longer passphrase', 'password_confirmation' => 'a much longer passphrase'])
            ->assertUnprocessable();

        expect(session()->has(Detours::PASSWORD_CHANGE))->toBeTrue();

        changePassword()->assertJsonPath('redirect', 'http://localhost/home');
    });

    it('goes back, not to a saved page on another site', function (string $url) {
        $this->withSession([Detours::PASSWORD_CHANGE => savedFor($this->user, $url)]);

        changePassword(json: false)->assertRedirect('/settings/password');

        expect(session()->has(Detours::PASSWORD_CHANGE))->toBeFalse();
    })->with(['http://localhost.evil.test/home', '//evil.test/home', 'https://localhost/home']);

    it('goes back, not to a page saved for another account', function () {
        $this->withSession([Detours::PASSWORD_CHANGE => savedFor(staff(), 'http://localhost/home')]);

        changePassword(json: false)->assertRedirect('/settings/password');
    });

    it('goes back, not to a page saved over an hour ago', function () {
        $this->get('/home', NAVIGATE);
        session()->put(Detours::PASSWORD_CHANGE.'.at', now()->getTimestamp() - Detours::LIFETIME - 1);

        changePassword(json: false)->assertRedirect('/settings/password');

        expect(session()->has(Detours::PASSWORD_CHANGE))->toBeFalse();
    });

    it('does not save the change-password page, or replace what was saved with it', function () {
        $this->get('/home', NAVIGATE);
        // The page saving itself, or being handed in as where to go.
        Route::middleware('web')->get('/settings/password', function (Request $request) {
            app(Detours::class)->remember($request, Detours::PASSWORD_CHANGE);
            app(Detours::class)->remember($request, Detours::PASSWORD_CHANGE, url('/settings/password?step=2'));

            return 'ok';
        });

        $this->get('/settings/password', NAVIGATE)->assertOk();

        expect(session(Detours::PASSWORD_CHANGE)['url'])->toBe('http://localhost/home');
    });

    it('goes back as before with nothing saved', function () {
        changePassword(json: false)->assertRedirect('/settings/password');
    });

    it('does not carry on to where enrolling was going', function () {
        $this->withSession([Detours::ENROLLMENT => savedFor($this->user)]);

        changePassword()->assertOk()->assertJsonMissingPath('redirect');

        expect(session()->has(Detours::ENROLLMENT))->toBeTrue();
    });

    it('saves nothing for keyring\'s own pages', function () {
        $this->get(route('keyring.sessions.index'), NAVIGATE)->assertRedirect('/settings/password');

        expect(session()->has(Detours::PASSWORD_CHANGE))->toBeFalse();
    });

    it('saves it for an app\'s own response too', function () {
        Keyring::respondWith(PasswordChangeRequiredResponse::class, fn () => new class implements PasswordChangeRequiredResponse
        {
            public function toResponse($request)
            {
                return redirect('/welcome/new-password');
            }
        });

        $this->get('/home', NAVIGATE)->assertRedirect('/welcome/new-password');

        changePassword()->assertJsonPath('redirect', 'http://localhost/home');
    });
});

describe('a password change the user chose', function () {
    it('goes nowhere new, forgets what a hold saved, and leaves enrolling\'s alone', function () {
        signIn();
        $this->withSession([Detours::ENROLLMENT => savedFor($this->user), Detours::PASSWORD_CHANGE => savedFor($this->user, 'http://localhost/home')]);

        $this->from('/settings/password')->put(route('user-password.update'), [
            'current_password' => 'password',
            'password' => 'a much longer passphrase',
            'password_confirmation' => 'a much longer passphrase',
        ])->assertRedirect('/settings/password')->assertSessionHas('status', 'password-updated');

        expect(session()->has(Detours::PASSWORD_CHANGE))->toBeFalse()
            ->and(session(Detours::ENROLLMENT)['url'])->toBe('http://localhost/invoices/42');
    });
});

/**
 * An app's own Detours, as docs/extending.md shows: it never saves a silent
 * authorize request, and notes every call so a test can see who used it.
 */
class SkipsSilentRequests extends Detours
{
    /** @var list<array{0: string, 1?: string, 2?: string}> */
    public static array $calls = [];

    protected function put(Request $request, string $key, string $url): void
    {
        static::$calls[] = ['put', $key, $url];

        if (Uri::of($url)->query()->get('prompt') !== 'none') {
            parent::put($request, $key, $url);
        }
    }

    public function pull(Request $request, string $key): ?string
    {
        static::$calls[] = ['pull', $key];

        return parent::pull($request, $key);
    }

    public function forget(Request $request): void
    {
        static::$calls[] = ['forget'];

        parent::forget($request);
    }
}

describe('an app\'s own detours', function () {
    beforeEach(function () {
        SkipsSilentRequests::$calls = [];
        $this->app->bind(Detours::class, SkipsSilentRequests::class);
    });

    it('is used when a user is sent to enroll, and when they have', function () {
        signIn();
        $this->get('/invoices/42', NAVIGATE)->assertRedirect('/settings/security');

        $this->get('/invoices/7?prompt=none', NAVIGATE)->assertRedirect('/settings/security');

        expect(addAuthenticatorApp()['continue'])->toBe('http://localhost/invoices/42')
            ->and(SkipsSilentRequests::$calls)->toBe([
                ['forget'],
                ['put', Detours::ENROLLMENT, 'http://localhost/invoices/42'],
                ['put', Detours::ENROLLMENT, 'http://localhost/invoices/7?prompt=none'],
                ['pull', Detours::ENROLLMENT],
            ]);
    });

    it('is used when a user is held for a new password, and when they have chosen one', function () {
        signIn();
        Keyring::requirePasswordChange($this->user);

        $this->get('/home', NAVIGATE)->assertRedirect('/settings/password');
        $this->get('/home?prompt=none', NAVIGATE)->assertRedirect('/settings/password');

        $this->putJson(route('user-password.update'), ['current_password' => 'password', 'password' => 'a much longer passphrase', 'password_confirmation' => 'a much longer passphrase'])
            ->assertJsonPath('redirect', 'http://localhost/home');

        expect(SkipsSilentRequests::$calls)->toBe([
            ['forget'],
            ['put', Detours::PASSWORD_CHANGE, 'http://localhost/home'],
            ['put', Detours::PASSWORD_CHANGE, 'http://localhost/home?prompt=none'],
            ['pull', Detours::PASSWORD_CHANGE],
        ]);
    });

    it('is handed the page a confirm was for, not the confirm page', function () {
        signIn();

        $this->get('/keys-only?prompt=none', NAVIGATE)->assertRedirect(route('keyring.confirm.challenge'));
        $this->get(route('keyring.confirm.challenge'), NAVIGATE)->assertRedirect('/settings/security');

        expect(session()->has(Detours::ENROLLMENT))->toBeFalse()
            ->and(SkipsSilentRequests::$calls)->toContain(['put', Detours::ENROLLMENT, 'http://localhost/keys-only?prompt=none']);
    });

    it('is what a sign in forgets with', function () {
        $this->withSession([Detours::ENROLLMENT => savedFor($this->user)]);

        signIn();

        expect(SkipsSilentRequests::$calls)->toBe([['forget']])
            ->and(session()->has(Detours::ENROLLMENT))->toBeFalse();
    });
});
