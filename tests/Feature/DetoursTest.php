<?php

declare(strict_types=1);

// Its own namespace, so its helpers can't collide with another file's.

namespace Keyring\Tests\Feature\Detours;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Keyring\Contracts\Responses\ConfirmationRequiredResponse;
use Keyring\Contracts\Responses\EnrollmentRequiredResponse;
use Keyring\Contracts\Responses\PasswordChangeRequiredResponse;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Login\Detours;
use Keyring\Login\Requirement;
use Keyring\Login\StepUp;
use Keyring\Models\Authenticator;
use Keyring\Sessions\RegisteredSession;
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

        expect(session(Detours::ENROLLMENT))->toBe(savedFor($this->user))
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

        expect(addAuthenticatorApp()['continue'])->toBe('http://localhost/keys-only');
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
