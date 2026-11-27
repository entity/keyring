<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Failed;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password as PasswordBroker;
use Illuminate\Support\Facades\Route;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enrollment\Enrollment;
use Keyring\Enrollment\EnrollmentStore;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Enums\SsoFailure;
use Keyring\Events\AuthenticatorAdded;
use Keyring\Events\AuthenticatorRemoved;
use Keyring\Events\FactorFailed;
use Keyring\Events\RegisteredSessionEnded;
use Keyring\Exceptions\SsoFailed;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\SingleSignOn;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use Keyring\Models\SecurityEvent;
use Keyring\Notifications\AuthenticatorAdded as AuthenticatorAddedNotice;
use Keyring\Notifications\SecondFactorFailed;
use Keyring\Risk\RiskLocks;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sso\AuthorizationRequest;
use Keyring\Sso\Identity;
use Keyring\Sso\PendingAuthorizations;
use Keyring\Testing\FakeIdentityProvider;
use Keyring\Tests\Fixtures\User;

const SSO_SUBJECT = '248289761001';

beforeEach(function () {
    Http::preventStrayRequests();
    Keyring::factors([Password::class, WebAuthn::passkeys(), Totp::class, RecoveryCodes::class, SingleSignOn::class]);

    $this->idp = new FakeIdentityProvider()->register('fake');
    // Keyring only registers its routes for single sign-on with a provider
    // configured, and this one was added after the app booted.
    reloadRoutes();
    $this->user = taylor();
});

/**
 * Click "Sign in with ..." and sign in at the provider: the callback URL it
 * sends the browser back to.
 */
function signInAtProvider(FakeIdentityProvider $idp, string $provider = 'fake', string $query = ''): string
{
    $url = test()->get(route('keyring.sso.redirect', $provider).$query)->assertRedirect()->headers->get('Location');

    return $idp->approve($url);
}

/**
 * Begin linking an account at the provider, as the signed-in user: the
 * provider's authorization URL.
 *
 * @param  array<string, string>  $headers
 */
function beginLink(string $provider = 'fake', array $headers = []): string
{
    return test()->postJson(route('keyring.authenticators.store', 'sso'), ['provider' => $provider], $headers)
        ->assertOk()
        ->assertJsonPath('factor', 'sso')
        ->assertJsonPath('enrollment.provider', $provider)
        ->json('enrollment.url');
}

function linkFor(User $user, string $subject = SSO_SUBJECT, string $provider = 'fake'): Authenticator
{
    return Authenticator::factory()->sso($provider, $subject)->for($user, 'authenticatable')->create();
}

function identity(string $provider = 'fake', string $subject = SSO_SUBJECT, string $issuer = 'https://idp.test', ?string $email = 'taylor@example.com'): Identity
{
    return new Identity(AuthorizationRequest::make($provider, SingleSignOn::LOGIN, SSO_CALLBACK), $provider, $issuer, $subject, $email, true);
}

describe('signing in', function () {
    it('offers each configured provider on the login page', function () {
        FakeIdentityProvider::github()->register('github');

        $this->getJson('/login')->assertOk()->assertJsonPath('props.providers', [
            ['name' => 'fake', 'label' => 'Fake', 'url' => route('keyring.sso.redirect', 'fake')],
            ['name' => 'github', 'label' => 'GitHub', 'url' => route('keyring.sso.redirect', 'github')],
        ]);
    });

    it('offers none, and has no routes for it, until the factor is registered', function () {
        Keyring::factors([Password::class]);

        $this->getJson('/login')->assertOk()->assertJsonPath('props.providers', []);
        $this->get(route('keyring.sso.redirect', 'fake'))->assertNotFound();
        $this->get(route('keyring.sso.callback', 'fake'))->assertNotFound();
    });

    it('answers 404 for a provider that is not configured', function () {
        $this->get(route('keyring.sso.redirect', 'nope'))->assertNotFound();
        $this->get(route('keyring.sso.callback', 'nope'))->assertNotFound();
    });

    it('sends the provider the one callback url every sign in and link uses', function () {
        $url = $this->get(route('keyring.sso.redirect', 'fake'))->assertRedirect()->headers->get('Location');

        expect($url)->toStartWith('https://idp.test/')
            ->and(authorizationQuery($url)['redirect_uri'])->toBe('http://localhost/auth/fake/callback');
    });

    it('starts the callback url where emailed links start', function () {
        Keyring::linkRootUsing(fn () => 'https://app.example.com/');

        expect(authorizationQuery($this->get(route('keyring.sso.redirect', 'fake'))->headers->get('Location'))['redirect_uri'])
            ->toBe('https://app.example.com/auth/fake/callback');
    });

    it('signs in the user who linked the account, and goes home', function () {
        $link = linkFor($this->user);

        $this->get(signInAtProvider($this->idp->signIn(['email' => 'taylor@new.example.com'])))->assertRedirect('/dashboard');

        $this->assertAuthenticatedAs($this->user);
        expect(logEntry('signed_in')->meta['factors'])->toBe(['sso'])
            ->and($link->fresh()->last_used_at)->not->toBeNull()
            ->and($link->fresh()->meta('email'))->toBe('taylor@new.example.com');
    });

    it('goes on to the page the user was sent to sign in for', function () {
        linkFor($this->user);
        $this->withSession(['url.intended' => 'http://localhost/invoices/42']);

        $this->get(signInAtProvider($this->idp))->assertRedirect('http://localhost/invoices/42');
    });

    it('remembers the browser when the button asked to', function () {
        linkFor($this->user);

        $remembered = $this->get(signInAtProvider($this->idp, query: '?remember=1'));

        expect(collect($remembered->headers->getCookies())->contains(fn ($cookie) => str_starts_with($cookie->getName(), 'remember_web_')))->toBeTrue();
    });

    it('does not remember the browser when only the callback asks to', function () {
        linkFor($this->user);

        $response = $this->get(signInAtProvider($this->idp).'&remember=1');

        expect(collect($response->headers->getCookies())->contains(fn ($cookie) => str_starts_with($cookie->getName(), 'remember_web_')))->toBeFalse();
    });

    it('still asks a user with a second factor for it', function () {
        linkFor($this->user);
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        $this->get(signInAtProvider($this->idp))->assertRedirect(route('keyring.login.challenge'));

        $this->assertGuest();
        $this->getJson(route('keyring.login.challenge'))->assertOk()->assertJsonPath('props.factor', 'totp')->assertJsonPath('props.alternatives', []);
    });

    it('refuses an account nobody linked like a wrong password', function () {
        $this->from('/login')->get(signInAtProvider($this->idp))->assertRedirect('/login')->assertSessionHasErrors(['email' => __('auth.failed')]);

        $this->assertGuest();
        expect(loggedTypes())->toBe(['factor_failed']);
    });

    it('never links or signs in an account by its email address', function () {
        $this->idp->signIn(['sub' => 'someone-else', 'email' => 'taylor@example.com', 'email_verified' => true]);
        linkFor($this->user);

        $this->get(signInAtProvider($this->idp))->assertRedirect('/login')->assertSessionHasErrors(['email' => __('auth.failed')]);

        $this->assertGuest();
        expect($this->user->keyring->of('sso'))->toHaveCount(1);
    });

    it('matches on the issuer as well as the subject', function () {
        Authenticator::factory()->sso('other', SSO_SUBJECT, 'https://other-idp.test')->for($this->user, 'authenticatable')->create();

        $this->get(signInAtProvider($this->idp))->assertSessionHasErrors(['email' => __('auth.failed')]);

        $this->assertGuest();
    });

    it('refuses an account the app keeps out like one nobody linked', function () {
        linkFor($this->user);
        Keyring::allowSignInWhen(fn () => false);

        $this->get(signInAtProvider($this->idp))->assertSessionHasErrors(['email' => __('auth.failed')]);

        $this->assertGuest();
    });

    it('refuses a user under a risk lock', function () {
        linkFor($this->user);
        app(RiskLocks::class)->lock($this->user, 600);

        $this->get(signInAtProvider($this->idp))->assertSessionHasErrors(['email' => __('auth.failed')]);

        $this->assertGuest();
    });

    it('counts sign ins against the per-ip limit', function () {
        config(['keyring.limits.per_ip' => 2]);

        $this->get(signInAtProvider($this->idp))->assertSessionHasErrors(['email' => __('auth.failed')]);
        $this->get(signInAtProvider($this->idp))->assertSessionHasErrors(['email' => __('auth.failed')]);
        linkFor($this->user);

        $this->get(signInAtProvider($this->idp))->assertRedirect('/login')->assertSessionHasErrors('email');

        $this->assertGuest();
        expect(session('errors')->first('email'))->not->toBe(__('auth.failed'))
            ->and(loggedTypes())->toContain('locked_out');
    });

    it('goes back to the login page quietly when the user said no at the provider', function () {
        $url = $this->get(route('keyring.sso.redirect', 'fake'))->headers->get('Location');

        $this->get($this->idp->deny($url))->assertRedirect(route('login'))->assertSessionHas('status', 'sso-cancelled')->assertSessionHasNoErrors();

        expect(loggedTypes())->toBe([]);
        $this->getJson('/login')->assertJsonPath('props.status', __('keyring::status.sso-cancelled'));
    });

    it('fails a callback the provider gets wrong, and notes it', function () {
        linkFor($this->user);
        $url = $this->get(route('keyring.sso.redirect', 'fake'))->headers->get('Location');

        $this->get($this->idp->withClaims(['aud' => 'someone-else'])->approve($url))
            ->assertRedirect(route('login'))
            ->assertSessionHasErrors(['email' => __('keyring::keyring.sso_failed', ['provider' => 'Fake'])]);

        $this->assertGuest();
        expect(logEntry('factor_failed')->authenticatable_id)->toBeNull();
    });

    it('takes each callback once', function () {
        linkFor($this->user);
        $callback = signInAtProvider($this->idp);
        $this->get($callback)->assertRedirect('/dashboard');
        Auth::logout();

        $this->get($callback)->assertSessionHasErrors(['email' => __('keyring::keyring.sso_failed', ['provider' => 'Fake'])]);

        $this->assertGuest();
    });

    it('refuses a state this browser was never given', function () {
        linkFor($this->user);
        $this->get(route('keyring.sso.redirect', 'fake'));

        $this->get(route('keyring.sso.callback', ['fake', 'code' => 'abc', 'state' => str_repeat('a', 43)]))
            ->assertSessionHasErrors(['email' => __('keyring::keyring.sso_failed', ['provider' => 'Fake'])]);
        $this->get(route('keyring.sso.callback', ['fake', 'code' => 'abc']))
            ->assertSessionHasErrors('email');

        $this->assertGuest();
    });

    it('refuses a callback for another provider\'s sign in', function () {
        linkFor($this->user);
        FakeIdentityProvider::github()->register('github');
        $callback = signInAtProvider($this->idp);

        $this->get(str_replace('/auth/fake/', '/auth/github/', $callback))->assertSessionHasErrors('email');

        $this->assertGuest();
    });

    it('says when the provider cannot be reached to start', function () {
        $this->idp->down();

        $this->from('/login')->get(route('keyring.sso.redirect', 'fake'))
            ->assertRedirect(route('login'))
            ->assertSessionHasErrors(['email' => __('keyring::keyring.sso_failed', ['provider' => 'Fake'])]);
    });

    it('leaves a signed-in user signed in, and the callback for later', function () {
        $other = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        linkFor($other);
        $callback = signInAtProvider($this->idp);
        $this->actingAs($this->user);

        $this->get($callback)->assertRedirect();

        $this->assertAuthenticatedAs($this->user);
        expect(app(PendingAuthorizations::class)->find(authorizationQuery($callback)['state']))->not->toBeNull();
    });

    it('does not start a sign in for a user who is signed in', function () {
        $this->actingAs($this->user)->get(route('keyring.sso.redirect', 'fake'))->assertRedirect();

        expect(session('keyring.sso'))->toBeNull();
    });

    it('signs in a user whose only way in is the provider', function () {
        $this->user->forceFill(['password' => null])->saveQuietly();
        linkFor($this->user);

        $this->get(signInAtProvider($this->idp))->assertRedirect('/dashboard');

        $this->assertAuthenticatedAs($this->user);
    });

    it('answers a sign in started from a form post like a wrong password', function () {
        linkFor($this->user);

        $this->postJson(route('keyring.login.factor', 'sso'))->assertUnprocessable()->assertJsonValidationErrors(['email' => __('auth.failed')]);

        $this->assertGuest();
    });

    it('shows problems on the username field', function () {
        config(['keyring.username' => 'name']);

        $this->get(signInAtProvider($this->idp))->assertSessionHasErrors(['name' => __('auth.failed')]);
    });

    it('leaves a provider that can\'t be built off the login page, and reports it', function () {
        Exceptions::fake();
        // Its client_id comes from an env var that isn't set.
        config(['keyring.sso.providers.broken' => ['driver' => 'oidc', 'issuer' => 'https://broken.test', 'client_id' => null]]);

        $this->getJson('/login')->assertOk()->assertJsonPath('props.providers', [
            ['name' => 'fake', 'label' => 'Fake', 'url' => route('keyring.sso.redirect', 'fake')],
        ]);

        Exceptions::assertReported(fn (InvalidArgumentException $e) => $e->getMessage() === 'Identity provider [broken] needs a client_id.');

        // The others still work, and it only throws once it's used.
        linkFor($this->user);
        $this->get(signInAtProvider($this->idp))->assertRedirect('/dashboard');
        Auth::logout();
        $this->get(route('keyring.sso.redirect', 'broken'))->assertInternalServerError();
    });

    it('reports a failure that says something is wrong, and none that users cause every day', function () {
        Exceptions::fake();
        linkFor($this->user);

        // Said no, and a state that's spent or unknown.
        $this->get($this->idp->deny($this->get(route('keyring.sso.redirect', 'fake'))->headers->get('Location')));
        $this->get(route('keyring.sso.callback', ['fake', 'code' => 'abc', 'state' => str_repeat('a', 43)]));

        Exceptions::assertNothingReported();

        $this->get($this->idp->withClaims(['aud' => 'someone-else'])->approve($this->get(route('keyring.sso.redirect', 'fake'))->headers->get('Location')));
        $this->idp->down();
        Cache::flush();
        $this->get(route('keyring.sso.redirect', 'fake'));

        Exceptions::assertReported(fn (SsoFailed $e) => $e->reason === SsoFailure::InvalidToken && ! $e->expected());
        Exceptions::assertReported(fn (SsoFailed $e) => $e->reason === SsoFailure::Unavailable);
        Exceptions::assertReportedCount(2);
    });

    it('spends a state an app started for something else, and isn\'t there for it', function (bool $signedIn) {
        linkFor($this->user);
        $callback = $this->idp->approve(Keyring::sso()->start('fake', 'sign-up', route('keyring.sso.callback', 'fake')));

        if ($signedIn) {
            $this->actingAs($this->user);
        }

        $this->get($callback)->assertNotFound();

        expect(app(PendingAuthorizations::class)->find(authorizationQuery($callback)['state']))->toBeNull()
            ->and($signedIn ? $this->user->keyring->refresh()->of('sso') : collect())->toHaveCount($signedIn ? 1 : 0);
        $signedIn ? $this->assertAuthenticatedAs($this->user) : $this->assertGuest();
    })->with(['for a guest' => false, 'for someone signed in' => true]);

    it('draws a guest\'s callbacks on the limit the redirect has', function () {
        Event::fake([FactorFailed::class]);
        $callback = route('keyring.sso.callback', ['fake', 'code' => 'abc', 'state' => str_repeat('a', 43)]);

        foreach (range(1, 60) as $try) {
            $this->get($callback)->assertRedirect(route('login'));
        }

        $this->get($callback)->assertTooManyRequests();
        $this->get(route('keyring.sso.redirect', 'fake'))->assertTooManyRequests();

        Event::assertDispatchedTimes(FactorFailed::class, 60);
    });

    it('never takes the username in Laravel\'s Failed event from the callback\'s query', function () {
        Event::fake([Failed::class]);

        $this->get(route('keyring.sso.callback', ['fake', 'code' => 'abc', 'state' => str_repeat('a', 43), 'email' => 'abigail@example.com']));

        Event::assertDispatched(Failed::class, fn (Failed $event) => $event->user === null && $event->credentials === ['email' => null]);
    });

    it('leaves a forwarded prefix out of the callback url', function () {
        TrustProxies::at('*');

        $url = $this->withHeader('X-Forwarded-Prefix', '/out?to=//evil.test')->get(route('keyring.sso.redirect', 'fake'))->headers->get('Location');

        expect(authorizationQuery($url)['redirect_uri'])->toBe('http://localhost/auth/fake/callback');

        TrustProxies::flushState();
    });

    it('tells a user who fails their second factor after the provider that the provider was used', function () {
        Notification::fake();
        $link = linkFor($this->user);
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        $failed = null;
        Event::listen(FactorFailed::class, function (FactorFailed $event) use (&$failed) {
            $failed = $event;
        });

        $this->get(signInAtProvider($this->idp))->assertRedirect(route('keyring.login.challenge'));
        $this->post(route('keyring.login.verify', 'totp'), ['code' => '000000'])->assertSessionHasErrors();

        expect($failed->afterFirstFactor())->toBeTrue()
            ->and($failed->afterPassword())->toBeFalse()
            ->and($failed->firstFactor()->factor)->toBe('sso')
            ->and(loggedTypes())->toContain('second_factor_failed');
        Notification::assertSentTo($this->user, SecondFactorFailed::class, fn (SecondFactorFailed $notice) => $notice->name === $link->name
            && $notice->subject() === 'Someone started signing in to your account'
            && str_contains($notice->intro(), 'signed in with Single sign-on (taylor@example.com)')
            && ! str_contains($notice->intro(), 'password'));
    });

    it('still says the password was used when it was', function () {
        Notification::fake();
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        $this->post(route('login.store'), ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));
        $this->post(route('keyring.login.verify', 'totp'), ['code' => '000000'])->assertSessionHasErrors();

        Notification::assertSentTo($this->user, SecondFactorFailed::class, fn (SecondFactorFailed $notice) => $notice->name === null
            && $notice->subject() === 'Someone entered your password');
    });
});

it('registers no routes for single sign-on without a provider, leaving the app its own', function () {
    config(['keyring.sso.providers' => []]);
    reloadRoutes();
    Route::get('/auth/github/callback', fn () => 'ours')->middleware('web');

    expect(Route::has('keyring.sso.redirect'))->toBeFalse()
        ->and(Route::has('keyring.sso.callback'))->toBeFalse();
    $this->get('/auth/github/callback?code=abc&state=xyz')->assertOk()->assertSee('ours');
    $this->getJson('/login')->assertOk()->assertJsonPath('props.providers', []);
});

describe('a frontend Laravel does not serve', function () {
    it('gets the url to send the user to', function () {
        $url = $this->getJson(route('keyring.sso.redirect', 'fake'))->assertOk()->json('url');

        expect($url)->toStartWith('https://idp.test/')
            ->and(session('keyring.sso'))->not->toBeNull();
    });

    it('has an inertia visit load the provider in full', function () {
        $response = $this->inertia()->get(route('keyring.sso.redirect', 'fake'))->assertStatus(409);

        expect($response->headers->get('X-Inertia-Location'))->toStartWith('https://idp.test/');
    });

    it('passes the callback on and gets the answer as json', function () {
        linkFor($this->user);

        $this->getJson(signInAtProvider($this->idp))->assertOk()->assertExactJson(['status' => 'authenticated', 'redirect' => 'http://localhost/dashboard']);

        $this->assertAuthenticatedAs($this->user);
    });

    it('is told a second factor is next', function () {
        linkFor($this->user);
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        $this->getJson(signInAtProvider($this->idp))->assertStatus(202)->assertJsonPath('page', 'challenge');
    });

    it('gets refusals as validation errors', function () {
        $this->getJson(signInAtProvider($this->idp))->assertUnprocessable()->assertJsonValidationErrors(['email' => __('auth.failed')]);

        $this->getJson(route('keyring.sso.callback', ['fake', 'code' => 'abc', 'state' => 'nope']))
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['email' => __('keyring::keyring.sso_failed', ['provider' => 'Fake'])]);

        new FakeIdentityProvider('https://down.idp.test')->register('down')->down();
        $this->getJson(route('keyring.sso.redirect', 'down'))->assertUnprocessable()->assertJsonValidationErrors(['email' => __('keyring::keyring.sso_failed', ['provider' => 'Down'])]);
    });

    it('gets a cancelled sign in as a status', function () {
        $url = $this->getJson(route('keyring.sso.redirect', 'fake'))->json('url');

        $this->getJson($this->idp->deny($url))->assertOk()->assertJson(['status' => 'sso-cancelled', 'page' => 'login']);
    });
});

describe('linking', function () {
    beforeEach(function () {
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1);
    });

    it('links an account at the provider, and says so', function () {
        Notification::fake();
        Event::fake([AuthenticatorAdded::class]);

        $callback = $this->idp->approve(beginLink(headers: ['Referer' => 'http://localhost/settings/security']));

        $this->get($callback)->assertRedirect('http://localhost/settings/security')->assertSessionHas('status', 'authenticator-added');

        $link = $this->user->keyring->refresh()->of('sso')->sole();
        expect($link->name)->toBe('Fake (taylor@example.com)')
            ->and($link->credential_id)->toBe(SingleSignOn::credentialId('https://idp.test', SSO_SUBJECT))
            ->and($link->meta)->toBe(['provider' => 'fake', 'issuer' => 'https://idp.test', 'subject' => SSO_SUBJECT, 'email' => 'taylor@example.com'])
            ->and($link->is_default)->toBeFalse()
            ->and(Keyring::result('authenticator'))->toMatchArray(['factor' => 'sso', 'provider' => 'fake', 'email' => 'taylor@example.com'])
            ->and(session()->has('keyring.enrollment.sso'))->toBeFalse();
        Event::assertDispatched(AuthenticatorAdded::class, fn (AuthenticatorAdded $event) => $event->authenticator->is($link));
    });

    it('sends the notice, logs it, and hands out no recovery codes', function () {
        Notification::fake();

        $this->get($this->idp->approve(beginLink()))->assertRedirect('http://localhost');

        Notification::assertSentTo($this->user, AuthenticatorAddedNotice::class);
        expect(loggedTypes())->toBe(['authenticator_added'])
            ->and($this->user->keyring->refresh()->of('recovery'))->toBeEmpty();
    });

    it('then signs the user in with it', function () {
        $this->get($this->idp->approve(beginLink()));
        Auth::logout();
        session()->flush();

        $this->get(signInAtProvider($this->idp))->assertRedirect('/dashboard');

        $this->assertAuthenticatedAs($this->user);
    });

    it('answers a frontend that passes the callback on with json', function () {
        $this->getJson($this->idp->approve(beginLink()))
            ->assertOk()
            ->assertJsonPath('status', 'authenticator-added')
            ->assertJsonPath('authenticator.factor', 'sso')
            ->assertJsonPath('authenticator.email', 'taylor@example.com')
            ->assertJsonPath('redirect', 'http://localhost');
    });

    it('links several providers, and several accounts at one', function () {
        $github = FakeIdentityProvider::github()->register('github');

        $this->get($this->idp->approve(beginLink()));
        $this->get($this->idp->signIn(['sub' => 'work', 'email' => 'taylor@work.example.com'])->approve(beginLink()));
        $this->get($github->approve(beginLink('github')));

        expect($this->user->keyring->refresh()->of('sso')->pluck('name')->sort()->values()->all())
            ->toBe(['Fake (taylor@example.com)', 'Fake (taylor@work.example.com)', 'GitHub (taylor@example.com)']);
    });

    it('names a link without an address after its provider', function () {
        $this->get($this->idp->signIn(['email' => null])->approve(beginLink()));

        expect($this->user->keyring->refresh()->of('sso')->sole()->name)->toBe('Fake');
    });

    it('only brings an account already linked to the user up to date', function () {
        Event::fake([AuthenticatorAdded::class]);
        $link = linkFor($this->user);
        $link->withMeta('provider', 'renamed')->save();

        $this->get($this->idp->signIn(['email' => 'taylor@new.example.com'])->approve(beginLink()))
            ->assertSessionHas('status', 'authenticator-updated');

        expect($this->user->keyring->refresh()->of('sso'))->toHaveCount(1)
            ->and($link->fresh()->meta('email'))->toBe('taylor@new.example.com')
            ->and($link->fresh()->meta('provider'))->toBe('fake');
        Event::assertNotDispatched(AuthenticatorAdded::class);
    });

    it('refuses an account linked to someone else, without saying whose', function () {
        $other = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        linkFor($other);

        $this->get($this->idp->approve(beginLink()))
            ->assertRedirect('http://localhost')
            ->assertSessionHasErrors(['provider' => __('keyring::keyring.sso_link_failed', ['provider' => 'Fake'])]);

        expect($this->user->keyring->refresh()->of('sso'))->toBeEmpty()
            ->and(logEntry('enrollment_refused')->meta)->toBe(['reason' => 'invalid'])
            ->and(session('errors')->first('provider'))->not->toContain('abigail');
    });

    it('needs a recent verification to start', function () {
        $this->freshAt(now()->subDay());

        $this->postJson(route('keyring.authenticators.store', 'sso'), ['provider' => 'fake'])->assertStatus(423);
    });

    it('needs the verification to still be recent when the provider sends the user back', function () {
        config(['keyring.changes_middleware' => ['keyring.fresh:5m']]);
        $callback = $this->idp->approve(beginLink());
        $this->travel(6)->minutes();

        $this->get($callback)->assertRedirect(route('keyring.confirm.challenge'));

        expect($this->user->keyring->refresh()->of('sso'))->toBeEmpty()
            ->and(session('url.intended'))->toBe($callback)
            ->and(app(PendingAuthorizations::class)->find(authorizationQuery($callback)['state']))->not->toBeNull();

        // Confirming sends the user back to the callback, which finishes it.
        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertRedirect($callback);
        $this->get($callback)->assertSessionHas('status', 'authenticator-added');

        expect($this->user->keyring->refresh()->of('sso'))->toHaveCount(1);
    });

    it('answers a frontend with a 423 when the verification is no longer recent at the callback', function () {
        config(['keyring.changes_middleware' => ['keyring.fresh:5m']]);
        $callback = $this->idp->approve(beginLink());
        $this->travel(6)->minutes();

        $this->getJson($callback)->assertStatus(423);

        expect($this->user->keyring->refresh()->of('sso'))->toBeEmpty();
    });

    it('needs a verified address to start, and still at the callback', function () {
        revealTakenAddresses();
        $this->user->forceFill(['email_verified_at' => null])->saveQuietly();

        $this->postJson(route('keyring.authenticators.store', 'sso'), ['provider' => 'fake'])->assertForbidden();

        $this->user->forceFill(['email_verified_at' => now()])->saveQuietly();
        $callback = $this->idp->approve(beginLink());
        $this->user->forceFill(['email_verified_at' => null])->saveQuietly();

        $this->get($callback)->assertForbidden();

        expect($this->user->keyring->refresh()->of('sso'))->toBeEmpty()
            ->and(SecurityEvent::query()->where('type', 'enrollment_refused')->pluck('meta')->all())->toBe([['reason' => 'not_allowed'], ['reason' => 'not_allowed']]);
    });

    it('refuses to finish a link for someone other than who started it', function () {
        $callback = $this->idp->approve(beginLink());
        $other = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);

        // The app signed someone else in on this browser, keeping the rest
        // of its session.
        $kept = ['keyring.sso' => session('keyring.sso'), 'keyring.enrollment.sso' => session('keyring.enrollment.sso')];
        $this->flushSession();
        app('auth')->forgetGuards();
        $this->actingAs($other)->withAssurance(Assurance::AAL1)->withSession($kept);

        $this->get($callback)->assertSessionHasErrors('provider');

        expect(Authenticator::query()->where('factor', 'sso')->count())->toBe(0)
            ->and(app(PendingAuthorizations::class)->find(authorizationQuery($callback)['state']))->toBeNull()
            ->and(logEntry('enrollment_refused')->authenticatable_id)->toBe($other->id);
    });

    it('sends a guest to sign in before it finishes', function () {
        $callback = $this->idp->approve(beginLink());
        Auth::logout();

        $this->get($callback)->assertRedirect(route('login'));

        expect(Authenticator::query()->where('factor', 'sso')->count())->toBe(0);
    });

    it('refuses a callback used again', function () {
        $callback = $this->idp->approve(beginLink());
        $this->get($callback);
        $this->user->authenticators()->where('factor', 'sso')->delete();

        $this->get($callback)->assertSessionHasErrors(['provider' => __('keyring::keyring.sso_link_failed', ['provider' => 'Fake'])]);

        expect($this->user->keyring->refresh()->of('sso'))->toBeEmpty();
    });

    it('refuses a state this browser was never given', function () {
        beginLink();

        $this->get(route('keyring.sso.callback', ['fake', 'code' => 'abc', 'state' => 'nope']))->assertSessionHasErrors('provider');

        expect(logEntry('enrollment_refused')->meta)->toBe(['reason' => 'invalid']);
    });

    it('goes back quietly when the user said no at the provider', function () {
        $this->get($this->idp->deny(beginLink()))->assertSessionHas('status', 'sso-cancelled')->assertSessionHasNoErrors();

        expect(loggedTypes())->toBe([]);
    });

    it('refuses a link whose enrollment is gone', function () {
        $callback = $this->idp->approve(beginLink());
        app(EnrollmentStore::class)->forget('sso');

        $this->get($callback)->assertSessionHasErrors(['provider' => __('keyring::keyring.enrollment_expired')]);

        expect($this->user->keyring->refresh()->of('sso'))->toBeEmpty();
    });

    it('refuses a link whose enrollment was replaced by a newer one', function () {
        $first = $this->idp->approve(beginLink());
        beginLink();

        $this->get($first)->assertSessionHasErrors(['provider' => __('keyring::keyring.enrollment_expired')]);
    });

    it('can only be confirmed by the provider\'s callback', function () {
        beginLink();

        $this->postJson(route('keyring.authenticators.confirm', 'sso'))->assertUnprocessable()->assertJsonValidationErrors(['email' => __('keyring::keyring.invalid')]);

        expect($this->user->keyring->refresh()->of('sso'))->toBeEmpty();
    });

    it('needs a provider that is configured', function () {
        $this->postJson(route('keyring.authenticators.store', 'sso'))->assertJsonValidationErrors('provider');
        $this->postJson(route('keyring.authenticators.store', 'sso'), ['provider' => 'nope'])->assertJsonValidationErrors('provider');
    });

    it('says when the provider cannot be reached to start', function () {
        $this->idp->down();

        $this->postJson(route('keyring.authenticators.store', 'sso'), ['provider' => 'fake'])
            ->assertJsonValidationErrors(['provider' => __('keyring::keyring.sso_failed', ['provider' => 'Fake'])]);
    });

    it('lets a user who signed in with the provider alone link another while that is recent', function () {
        $this->user->forceFill(['password' => null])->saveQuietly();
        linkFor($this->user);
        Auth::logout();
        session()->flush();
        $this->get(signInAtProvider($this->idp))->assertRedirect('/dashboard');

        $this->get($this->idp->signIn(['sub' => 'work'])->approve(beginLink()))->assertSessionHas('status', 'authenticator-added');

        expect($this->user->keyring->refresh()->of('sso'))->toHaveCount(2);
    });
});

describe('unlinking', function () {
    beforeEach(function () {
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1);
    });

    it('removes a link like any other sign-in method', function () {
        Event::fake([AuthenticatorRemoved::class]);
        $link = linkFor($this->user);

        $this->deleteJson(route('keyring.authenticators.destroy', $link->id))->assertOk()->assertJsonPath('status', 'authenticator-removed');

        expect(Authenticator::find($link->id))->toBeNull();
        Event::assertDispatched(AuthenticatorRemoved::class);
    });

    it('keeps the last way in for a user whose only way in is the provider', function () {
        $this->user->forceFill(['password' => null])->saveQuietly();
        $link = linkFor($this->user);

        $this->deleteJson(route('keyring.authenticators.destroy', $link->id))->assertJsonValidationErrors(['authenticator' => __('keyring::keyring.last_factor')]);

        $second = linkFor($this->user, 'work');
        $this->deleteJson(route('keyring.authenticators.destroy', $second->id))->assertOk();

        expect(Authenticator::find($link->id))->not->toBeNull();
    });

    it('does not count a link as the second factor that keeps recovery codes', function () {
        $this->user->forceFill(['password' => 'a much longer password'])->saveQuietly();
        linkFor($this->user);
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

        $this->withAssurance(Assurance::AAL2)->deleteJson(route('keyring.authenticators.destroy', $totp->id), ['password' => 'a much longer password'])->assertOk();

        expect($this->user->keyring->refresh()->of('recovery'))->toBeEmpty()
            ->and($this->user->keyring->of('sso'))->toHaveCount(1);
    });

    it('never lets a link be made the default', function () {
        $link = linkFor($this->user);

        $this->patchJson(route('keyring.authenticators.update', $link->id), ['default' => true])->assertJsonValidationErrors('default');
        $this->patchJson(route('keyring.authenticators.update', $link->id), ['name' => 'Work Google'])->assertOk();

        expect($link->fresh())->is_default->toBeFalse()->name->toBe('Work Google');
    });

    it('makes the next second factor the default, not the link', function () {
        linkFor($this->user);

        $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');
        $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();

        expect($this->user->keyring->refresh()->default()->factor)->toBe('totp')
            ->and($this->user->keyring->of('totp')->sole()->is_default)->toBeTrue();
    });
});

it('unlinks every provider when the password is reset, and keeps second factors', function () {
    Event::fake([AuthenticatorRemoved::class]);
    $link = linkFor($this->user);
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->post(route('password.update'), [
        'token' => PasswordBroker::broker()->createToken($this->user),
        'email' => 'taylor@example.com',
        'password' => 'a new password',
        'password_confirmation' => 'a new password',
    ])->assertRedirect(route('login'));

    expect(Authenticator::find($link->id))->toBeNull()
        ->and(Authenticator::find($totp->id))->not->toBeNull();
    Event::assertDispatched(AuthenticatorRemoved::class, fn (AuthenticatorRemoved $event) => $event->authenticator->is($link));
});

it('unlinks providers on reset before signing out, and again after', function () {
    $link = linkFor($this->user);
    $now = now()->getTimestamp();
    app(SessionRegistry::class)->save(new RegisteredSession('elsewhere', (string) $this->user->id, RegisteredSession::typeOf($this->user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600));

    // What happened, in order. The sign-out stands in for a session that
    // linked an account while the first look ran, and was then signed out.
    $order = [];
    Event::listen(AuthenticatorRemoved::class, function (AuthenticatorRemoved $event) use (&$order) {
        $order[] = $event->authenticator->meta('subject');
    });
    Event::listen(RegisteredSessionEnded::class, function () use (&$order) {
        $order[] = 'signed out';
        linkFor($this->user, 'linked meanwhile');
    });

    $this->post(route('password.update'), [
        'token' => PasswordBroker::broker()->createToken($this->user),
        'email' => 'taylor@example.com',
        'password' => 'a much longer new password',
        'password_confirmation' => 'a much longer new password',
    ])->assertRedirect(route('login'));

    expect($order)->toBe([SSO_SUBJECT, 'signed out', 'linked meanwhile'])
        ->and(Authenticator::query()->where('factor', 'sso')->exists())->toBeFalse();
});

it('unlinks a provider on reset even while the factor is not registered', function () {
    $link = linkFor($this->user);
    Keyring::factors([Password::class]);

    $this->post(route('password.update'), [
        'token' => PasswordBroker::broker()->createToken($this->user),
        'email' => 'taylor@example.com',
        'password' => 'a much longer new password',
        'password_confirmation' => 'a much longer new password',
    ])->assertRedirect(route('login'));

    expect(Authenticator::find($link->id))->toBeNull();
});

describe('the factor', function () {
    it('shows a link with its provider and address', function () {
        expect(Keyring::factor('sso')->present(linkFor($this->user)))->toMatchArray([
            'factor' => 'sso',
            'name' => 'Single sign-on (taylor@example.com)',
            'provider' => 'fake',
            'email' => 'taylor@example.com',
        ]);
    });

    it('counts as the same kind of proof as a password, and only starts a sign in', function () {
        $factor = Keyring::factor('sso');

        expect($factor->categories(linkFor($this->user)))->toBe([Category::Knowledge])
            ->and($factor->startsLogin())->toBeTrue()
            ->and($factor->answersChallenges())->toBeFalse();
    });

    it('verifies only the identity the callback brought', function () {
        $factor = Keyring::factor('sso');
        $link = linkFor($this->user);
        $attempt = Attempt::start(Purpose::Login, $this->user);

        $request = Request::create('/');
        expect($factor->verify($attempt, $link, $request))->toBeNull();

        $request->attributes->set(SingleSignOn::IDENTITY, identity(subject: 'someone-else'));
        expect($factor->verify($attempt, $link, $request))->toBeNull();

        $request->attributes->set(SingleSignOn::IDENTITY, identity());
        expect($factor->verify($attempt, $link, $request))->not->toBeNull();
    });

    it('confirms only an identity from the provider the link was started with', function () {
        FakeIdentityProvider::github()->register('github');
        $request = Request::create('/');
        $request->attributes->set(SingleSignOn::IDENTITY, identity('github'));

        expect(Keyring::factor('sso')->confirmEnrollment($this->user, Enrollment::make('sso', state: ['provider' => 'fake']), $request))->toBeNull();
    });

    it('names each account at a provider by its issuer and subject, at a fixed length', function () {
        expect(SingleSignOn::credentialId('https://idp.test', SSO_SUBJECT))->toBe('sso:'.hash('sha256', "https://idp.test\0".SSO_SUBJECT))
            ->and(SingleSignOn::credentialId('https://idp.test', 'someone else'))->not->toBe(SingleSignOn::credentialId('https://idp.test', SSO_SUBJECT))
            ->and(SingleSignOn::credentialId('https://idp.test/x', SSO_SUBJECT))->not->toBe(SingleSignOn::credentialId('https://idp.test', SSO_SUBJECT));
    });
});
