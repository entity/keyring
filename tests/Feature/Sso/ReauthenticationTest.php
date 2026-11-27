<?php

declare(strict_types=1);

use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Keyring\Enums\Assurance;
use Keyring\Enums\Purpose;
use Keyring\Enums\SsoFailure;
use Keyring\Enums\SsoFreshness;
use Keyring\Events\Confirmed;
use Keyring\Events\FactorFailed;
use Keyring\Events\FactorVerified;
use Keyring\Exceptions\SsoFailed;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\SingleSignOn;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Attempt;
use Keyring\Login\AttemptStore;
use Keyring\Login\Requirement;
use Keyring\Login\StepUp;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sso\AuthorizationRequest;
use Keyring\Sso\Identity;
use Keyring\Sso\PendingAuthorizations;
use Keyring\Sso\Providers\GitHubProvider;
use Keyring\Sso\Providers\GoogleProvider;
use Keyring\Sso\Providers\OidcProvider;
use Keyring\Testing\FakeIdentityProvider;
use Keyring\Tests\Fixtures\User;

// How a sign in with a provider counts toward a recent verification, and
// confirming a step-up by going back to the provider.
beforeEach(function () {
    Http::preventStrayRequests();
    Keyring::factors([Password::class, Totp::class, RecoveryCodes::class, SingleSignOn::class]);

    // Google only says when the user signed in once that's set up for the
    // app, so it isn't asked unless the config says it can be. GitHub can
    // never be asked: its sign ins only count when the config opts it into
    // a round trip.
    $this->google = FakeIdentityProvider::google()->register('google', ['freshness' => 'reauthenticate']);
    $this->github = FakeIdentityProvider::github()->register('github', ['freshness' => 'round_trip']);
    reloadRoutes();
    protectedPages();

    $this->user = taylor(['password' => null]);
});

/**
 * A page that needs a recent verification, and one that needs AAL2.
 */
function protectedPages(): void
{
    Route::get('/settings/danger', fn () => 'danger zone')->middleware(['web', 'auth', 'keyring.fresh:15m']);
    Route::get('/billing', fn () => 'billing')->middleware(['web', 'auth', 'keyring:aal2']);
}

function googleLink(User $user, string $subject = '42'): Authenticator
{
    return Authenticator::factory()->sso('google', $subject, GoogleProvider::ISSUER)->for($user, 'authenticatable')->create();
}

function githubLink(User $user): Authenticator
{
    return Authenticator::factory()->sso('github', '583231', GitHubProvider::ISSUER)->for($user, 'authenticatable')->create();
}

/**
 * Signed in, with nothing proved in the last hour.
 */
function signedInLongAgo(User $user): void
{
    test()->actingAs($user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());
}

/**
 * Sign in with the provider through Keyring's own button.
 */
function signInThrough(FakeIdentityProvider $idp, string $provider): void
{
    test()->get($idp->approve(test()->get(route('keyring.sso.redirect', $provider))->headers->get('Location')));
}

/**
 * Ask for the page that needs a recent verification, open the confirm page,
 * and follow its link to the provider: the authorization URL.
 */
function confirmAtProvider(string $page = '/settings/danger'): string
{
    test()->get($page)->assertRedirect(route('keyring.confirm.challenge'));

    $url = test()->getJson(route('keyring.confirm.challenge', 'sso'))->assertOk()->assertJsonPath('props.factor', 'sso')->json('props.challenge.url');

    return test()->get($url)->assertRedirect()->headers->get('Location');
}

describe('signing in', function () {
    it('asks a provider that can be asked for auth_time, and counts a sign in let straight through as no more recent than its session', function () {
        $this->freezeSecond();
        googleLink($this->user);
        $this->google->signIn(['sub' => '42'])->signedInAt(now()->subHour());

        $url = $this->get(route('keyring.sso.redirect', 'google'))->headers->get('Location');
        expect(authorizationQuery($url))->toMatchArray(['claims' => '{"id_token":{"auth_time":{"essential":true}}}'])
            ->not->toHaveKeys(['max_age', 'prompt', 'login_hint']);

        $this->get($this->google->approve($url))->assertRedirect('/dashboard');

        $this->assertAuthenticatedAs($this->user);
        // Signed in, and at its level from now...
        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1);
        $verification = app(SessionAssurance::class)->all()[0];
        expect($verification->at)->toBe(now()->getTimestamp())
            ->and($verification->authenticatedAt)->toBe(now()->subHour()->getTimestamp());

        // ...but proved an hour ago, so it's no recent verification.
        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
        $this->postJson(route('keyring.authenticators.store', 'totp'))->assertStatus(423);
    });

    it('counts a sign in the provider just asked for as recent', function () {
        googleLink($this->user);
        $this->google->signIn(['sub' => '42']);

        signInThrough($this->google, 'google');

        $this->get('/settings/danger')->assertOk()->assertSee('danger zone');
    });

    it('never counts a sign in as recent when a provider that should say when doesn\'t', function () {
        googleLink($this->user);
        $this->google->signIn(['sub' => '42'])->withClaims(['auth_time' => null]);

        signInThrough($this->google, 'google');

        $this->assertAuthenticatedAs($this->user);
        expect(app(SessionAssurance::class)->all()[0]->provedAt())->toBe(0);
        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));

        // A confirm through the provider asks it for a new sign in, which
        // it has to say the time of.
        $url = $this->get($this->getJson(route('keyring.confirm.challenge'))->json('props.challenge.url'))->headers->get('Location');
        expect(authorizationQuery($url))->toMatchArray(['max_age' => '0']);

        $this->google->withClaims(['auth_time' => now()->getTimestamp()]);
        $this->get($this->google->approve($url))->assertRedirect('http://localhost/settings/danger');
        $this->get('/settings/danger')->assertOk();
    });

    it('keeps a sign in it doesn\'t know the time of at its level, and doesn\'t end it with sessions.end_on_lapse', function () {
        config(['keyring.sessions.end_on_lapse' => true]);
        googleLink($this->user);
        $this->google->signIn(['sub' => '42'])->withClaims(['auth_time' => null]);

        signInThrough($this->google, 'google');

        expect(app(SessionAssurance::class)->all()[0]->authenticatedAt)->toBe(Verification::UNKNOWN)
            ->and(app(SessionAssurance::class)->signedInLevel())->toBe(Assurance::AAL1);

        Route::get('/account', fn () => 'account')->middleware(['web', 'auth', 'keyring:aal1']);
        $this->travel(5)->minutes();
        $this->get('/account')->assertOk();

        $this->assertAuthenticatedAs($this->user);
        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1);
    });

    it('goes by the provider a sign in came through, after the link\'s was renamed in the config', function (?int $authTime, int $authenticatedAt) {
        $idp = new FakeIdentityProvider()->register('oidc');
        $link = Authenticator::factory()->sso('oidc', '42', $idp->issuer)->for($this->user, 'authenticatable')->create();

        // The operator renames "oidc" to "okta": the link still has the old name.
        config(['keyring.sso.providers.okta' => config('keyring.sso.providers.oidc'), 'keyring.sso.providers.oidc' => null]);
        config(['keyring.sso.providers' => array_filter(config('keyring.sso.providers'))]);
        $idp->signIn(['sub' => '42'])->withClaims(['auth_time' => $authTime]);

        signInThrough($idp, 'okta');

        $this->assertAuthenticatedAs($this->user);
        expect(app(SessionAssurance::class)->all()[0]->authenticatedAt)->toBe($authenticatedAt)
            ->and($link->fresh()->meta('provider'))->toBe('okta');

        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
        $this->getJson(route('keyring.confirm.challenge'))->assertOk()->assertJsonPath('props.factor', 'sso')->assertJsonPath('props.challenge.provider', 'okta');
    })->with([
        'an hour ago' => fn () => [now()->subHour()->getTimestamp(), now()->subHour()->getTimestamp()],
        'not said' => [null, Verification::UNKNOWN],
    ]);

    it('doesn\'t ask Google for auth_time by default, and never counts its sign ins as recent', function () {
        config(['keyring.sso.providers.google.freshness' => null]);
        googleLink($this->user);
        $this->google->signIn(['sub' => '42']);

        $url = $this->get(route('keyring.sso.redirect', 'google'))->headers->get('Location');
        expect(authorizationQuery($url))->not->toHaveKey('claims');

        $this->get($this->google->approve($url))->assertRedirect('/dashboard');

        $this->assertAuthenticatedAs($this->user);
        expect(app(SessionAssurance::class)->all()[0]->authenticatedAt)->toBe(Verification::UNKNOWN);
        // With nothing else, there's nothing to confirm with.
        $this->getJson('/settings/danger')->assertForbidden()->assertJsonPath('status', 'enroll-first');
    });

    it('asks an OpenID Connect provider for auth_time with the claims parameter only where its discovery takes one', function (?bool $supported, bool $asked) {
        new FakeIdentityProvider()->register('fake')->withDiscovery(['claims_parameter_supported' => $supported]);

        expect(array_key_exists('claims', authorizationQuery(ssoStart())))->toBe($asked);
    })->with([
        'supported' => [true, true],
        'not supported' => [false, false],
        'not said' => [null, false],
    ]);

    it('keeps the claims the config asks for alongside auth_time', function () {
        new FakeIdentityProvider()->register('fake', ['parameters' => ['claims' => '{"userinfo":{"email":null},"id_token":{"acr":{"essential":true}}}']])
            ->withDiscovery(['claims_parameter_supported' => true]);

        expect(json_decode(authorizationQuery(ssoStart())['claims'], true))->toBe([
            'userinfo' => ['email' => null],
            'id_token' => ['acr' => ['essential' => true], 'auth_time' => ['essential' => true]],
        ]);

        config(['keyring.sso.providers.fake.parameters.claims' => 'not json']);
        expect(authorizationQuery(ssoStart())['claims'])->toBe('{"id_token":{"auth_time":{"essential":true}}}');
    });

    it('counts a sign in with a provider that never says when as recent', function () {
        githubLink($this->user);

        signInThrough($this->github, 'github');

        expect(app(SessionAssurance::class)->all()[0]->authenticatedAt)->toBeNull();
        $this->get('/settings/danger')->assertOk();
    });

    it('takes no auth_time from a provider that isn\'t asked for one', function () {
        $idp = new FakeIdentityProvider()->register('fake', ['freshness' => 'round_trip']);
        Authenticator::factory()->sso('fake', '42', $idp->issuer)->for($this->user, 'authenticatable')->create();
        $idp->signIn(['sub' => '42'])->signedInAt(now()->subDay());

        signInThrough($idp, 'fake');

        $this->assertAuthenticatedAs($this->user);
        expect(app(SessionAssurance::class)->all()[0]->authenticatedAt)->toBeNull();
        $this->get('/settings/danger')->assertOk();
    });

    it('takes no auth_time from the future', function () {
        $this->freezeSecond();
        googleLink($this->user);
        $this->google->signIn(['sub' => '42'])->signedInAt(now()->addHour());

        signInThrough($this->google, 'google');

        expect(app(SessionAssurance::class)->all()[0]->provedAt())->toBe(now()->getTimestamp());
        $this->get('/settings/danger')->assertOk();
    });

    it('asks for the second factor on a page that needs AAL2, building on the sign in', function () {
        Keyring::require(Requirement::aal1());
        githubLink($this->user);
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        signInThrough($this->github, 'github');
        $this->assertAuthenticatedAs($this->user);

        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
        $this->getJson(route('keyring.confirm.challenge'))->assertOk()->assertJsonPath('props.factor', 'totp')->assertJsonPath('props.alternatives', []);
    });
});

describe('linking', function () {
    it('counts a link the provider let straight through as no more recent than its session', function (string $provider, bool $fresh) {
        $this->user->forceFill(['password' => 'password'])->saveQuietly();
        // The password was proved 14 minutes ago.
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subMinutes(14));
        $idp = $provider === 'google' ? $this->google : $this->github;
        $idp->signIn(['sub' => '42', 'id' => 42])->signedInAt(now()->subDay());

        $url = $this->postJson(route('keyring.authenticators.store', 'sso'), ['provider' => $provider])->assertOk()->json('enrollment.url');
        $this->get($idp->approve($url))->assertSessionHas('status', 'authenticator-added');

        $this->travel(5)->minutes();

        $fresh
            ? $this->get('/settings/danger')->assertOk()
            : $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
    })->with([
        'at a provider that can be asked' => ['google', false],
        'at one that can\'t' => ['github', true],
    ]);
});

describe('confirming', function () {
    beforeEach(function () {
        $this->link = googleLink($this->user);
        $this->google->signIn(['sub' => '42'])->signedInAt(now()->subDay());
        signedInLongAgo($this->user);
    });

    it('offers the link on the confirm page, with where to send the user', function () {
        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));

        $this->getJson(route('keyring.confirm.challenge'))
            ->assertOk()
            ->assertJsonPath('props.factor', 'sso')
            ->assertJsonPath('props.authenticator.provider', 'google')
            ->assertJsonPath('props.challenge', [
                'provider' => 'google',
                'label' => 'Google',
                'url' => route('keyring.sso.confirm', ['authenticator' => $this->link->id]),
            ]);
    });

    it('signs the user in again at the provider, and goes on to the page', function () {
        Event::fake([Confirmed::class, FactorVerified::class]);

        $url = confirmAtProvider();

        expect(authorizationQuery($url))->toMatchArray([
            'max_age' => '0',
            'claims' => '{"id_token":{"auth_time":{"essential":true}}}',
            'login_hint' => 'taylor@example.com',
        ])->not->toHaveKey('prompt');

        $this->get($this->google->approve($url))->assertRedirect('http://localhost/settings/danger');

        expect($this->google->authenticatedAt)->toBe(now()->getTimestamp());
        $this->get('/settings/danger')->assertOk()->assertSee('danger zone');
        $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk();
        Event::assertDispatched(Confirmed::class, fn (Confirmed $event) => $event->user->is($this->user));
        Event::assertDispatched(FactorVerified::class, fn (FactorVerified $event) => $event->authenticator->is($this->link));
    });

    it('sends no login_hint for a link without an address', function () {
        $this->link->forceFill(['meta' => [...$this->link->meta, 'email' => null]])->save();

        expect(authorizationQuery(confirmAtProvider()))->not->toHaveKey('login_hint');
    });

    it('asks an OpenID Connect provider for prompt=login with max_age, and Microsoft for prompt=login alone', function (string $driver, array $asked, array $notAsked) {
        $idp = match ($driver) {
            'oidc' => new FakeIdentityProvider()->register('fake'),
            'microsoft' => FakeIdentityProvider::microsoft()->withAuthTimeClaim()->register('fake'),
        };
        $this->link->delete();
        $link = Authenticator::factory()->sso('fake', '42', $idp->tokenIssuer())->for($this->user, 'authenticatable')->create();
        $idp->signIn(['sub' => '42'])->signedInAt(now()->subDay());

        $url = confirmAtProvider();

        expect(authorizationQuery($url))->toMatchArray($asked)->not->toHaveKeys($notAsked);

        $this->get($idp->approve($url))->assertRedirect('http://localhost/settings/danger');
        $this->get('/settings/danger')->assertOk();
        expect($link->fresh()->last_used_at)->not->toBeNull();
    })->with([
        'oidc' => ['oidc', ['max_age' => '0', 'prompt' => 'login', 'login_hint' => 'taylor@example.com'], ['claims']],
        'microsoft' => ['microsoft', ['prompt' => 'login', 'login_hint' => 'taylor@example.com'], ['max_age', 'claims']],
    ]);

    it('takes however long the user spends at the provider, from when they were sent there', function () {
        $url = confirmAtProvider();

        // They sign in a little after they're sent, then take their time
        // over the provider's own second factor.
        $this->travel(5)->seconds();
        $callback = $this->google->approve($url);
        $this->travel(90)->seconds();

        $this->get($callback)->assertRedirect('http://localhost/settings/danger');
        $this->get('/settings/danger')->assertOk();
    });

    it('takes a sign in at the provider from just before the user was sent there, as its clock may be behind', function () {
        $this->google->ignoringReauthentication()->signedInAt(now()->subSeconds(OidcProvider::LEEWAY - 10));

        $this->get($this->google->approve(confirmAtProvider()))->assertRedirect('http://localhost/settings/danger');
    });

    it('refuses a sign in at the provider from before the user was sent there', function () {
        Exceptions::fake();
        $this->google->ignoringReauthentication()->signedInAt(now()->subSeconds(OidcProvider::LEEWAY + 1));

        $this->get($this->google->approve(confirmAtProvider()))
            ->assertRedirect(route('keyring.confirm.challenge'))
            ->assertSessionHasErrors(['email' => __('keyring::keyring.sso_failed', ['provider' => 'Google'])]);

        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
        Exceptions::assertReported(fn (SsoFailed $e) => $e->reason === SsoFailure::StaleAuthentication && str_contains($e->getMessage(), 'longer ago'));
    });

    it('refuses another account at the provider, even one the user linked too', function () {
        Event::fake([FactorFailed::class]);
        googleLink($this->user, '43');
        $this->get('/settings/danger');
        $url = $this->get(route('keyring.sso.confirm', ['authenticator' => $this->link->id]))->assertRedirect()->headers->get('Location');

        $this->get($this->google->signIn(['sub' => '43'])->approve($url))
            ->assertRedirect(route('keyring.confirm.challenge'))
            ->assertSessionHasErrors(['email' => __('keyring::keyring.invalid')]);

        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
        Event::assertDispatched(FactorFailed::class, fn (FactorFailed $event) => $event->factor === 'sso' && $event->attempt?->purpose === Purpose::Confirm);
    });

    it('refuses a confirm finished by someone other than who started it', function () {
        $url = confirmAtProvider();
        $other = taylor(['email' => 'abigail@example.com', 'password' => null]);
        googleLink($other, '43');

        // The app signed someone else in on this browser, keeping the rest
        // of its session.
        $kept = ['keyring.sso' => session('keyring.sso'), AttemptStore::key(Purpose::Confirm) => session(AttemptStore::key(Purpose::Confirm))];
        $this->flushSession();
        app('auth')->forgetGuards();
        signedInLongAgo($other);
        $this->withSession($kept);

        $this->get($this->google->signIn(['sub' => '43'])->approve($url))
            ->assertRedirect(route('keyring.confirm.challenge'))
            ->assertSessionHasErrors(['email' => __('keyring::keyring.expired')]);

        expect(app(PendingAuthorizations::class)->find(authorizationQuery($url)['state']))->toBeNull();
        $this->assertAuthenticatedAs($other);
    });

    it('refuses a provider that doesn\'t say when the user signed in, and says how to fix it', function () {
        Exceptions::fake();
        $this->google->withClaims(['auth_time' => null]);

        $this->get($this->google->approve(confirmAtProvider()))->assertSessionHasErrors('email');

        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
        Exceptions::assertReported(fn (SsoFailed $e) => $e->reason === SsoFailure::StaleAuthentication
            && str_contains($e->getMessage(), "didn't say")
            && str_contains($e->getMessage(), '"freshness" to "never"'));
    });

    it('refuses an auth_time from the future', function () {
        $this->google->withClaims(['auth_time' => now()->addHour()->getTimestamp()]);

        $this->get($this->google->approve(confirmAtProvider()))->assertSessionHasErrors('email');

        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
    });

    it('refuses a confirm whose attempt is over', function () {
        $url = confirmAtProvider();
        app(AttemptStore::class)->forget(Purpose::Confirm);

        $this->get($this->google->approve($url))->assertRedirect(route('keyring.confirm.challenge'))->assertSessionHasErrors(['email' => __('keyring::keyring.expired')]);

        $url = confirmAtProvider();
        // Replaced by one that asks for something else.
        app(AttemptStore::class)->start(Purpose::Confirm, $this->user, requirement: Requirement::aal1()->withoutRecoveryCodes());

        $this->get($this->google->approve($url))->assertSessionHasErrors(['email' => __('keyring::keyring.expired')]);
    });

    it('fails a confirm whose attempt ran out of guesses, and counts it', function () {
        Event::fake([FactorFailed::class]);
        $url = confirmAtProvider();
        $attempt = app(AttemptStore::class)->current(Purpose::Confirm);
        $attempt->exhausted = true;
        app(AttemptStore::class)->save($attempt);

        $this->get($this->google->approve($url))->assertSessionHasErrors('email');

        Event::assertDispatched(FactorFailed::class);
        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
    });

    it('goes back to the confirm page quietly when the user said no', function () {
        $this->get($this->google->deny(confirmAtProvider()))
            ->assertRedirect(route('keyring.confirm.challenge'))
            ->assertSessionHas('status', 'sso-cancelled')
            ->assertSessionHasNoErrors();
    });

    it('counts confirms against the rate limits', function () {
        config(['keyring.limits.per_ip' => 2]);

        foreach (['43', '44'] as $subject) {
            $this->get($this->google->signIn(['sub' => $subject])->approve(confirmAtProvider()))->assertSessionHasErrors(['email' => __('keyring::keyring.invalid')]);
        }

        $this->get($this->google->signIn(['sub' => '42'])->approve(confirmAtProvider()))->assertRedirect(route('keyring.confirm.challenge'))->assertSessionHasErrors('email');

        expect(session('errors')->first('email'))->not->toBe(__('keyring::keyring.invalid'))
            ->and(loggedTypes())->toContain('locked_out');
        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
    });

    it('takes no confirm posted to the confirm page', function () {
        $this->get('/settings/danger');
        $this->getJson(route('keyring.confirm.challenge'));

        $this->postJson(route('keyring.confirm.verify', 'sso'))->assertUnprocessable()->assertJsonValidationErrors(['email' => __('keyring::keyring.invalid')]);
    });

    it('needs a confirm in progress to start one', function () {
        app(AttemptStore::class)->forget(Purpose::Confirm);

        $this->get(route('keyring.sso.confirm', ['authenticator' => $this->link->id]))
            ->assertRedirect(route('keyring.confirm.challenge'))
            ->assertSessionHasErrors(['email' => __('keyring::keyring.expired')]);
    });

    it('answers 404 for a link the confirm doesn\'t offer', function () {
        $this->get('/settings/danger');
        googleLink($this->user, '43');

        $this->get(route('keyring.sso.confirm', ['authenticator' => 'nope']))->assertNotFound();
        // With two links and neither named nor shown, it can't tell which.
        $this->get(route('keyring.sso.confirm'))->assertNotFound();
    });

    it('starts with the link the page showed when none is named', function () {
        googleLink($this->user, '43');
        $this->get('/settings/danger');
        $this->getJson(route('keyring.confirm.challenge', 'sso').'?authenticator='.$this->link->id)->assertJsonPath('props.authenticator.id', $this->link->id);

        $url = $this->get(route('keyring.sso.confirm'))->headers->get('Location');

        $this->get($this->google->approve($url))->assertRedirect('http://localhost/settings/danger');
    });

    it('says when the provider cannot be reached to start', function () {
        $this->get('/settings/danger');
        $this->google->down();

        $this->get(route('keyring.sso.confirm'))
            ->assertRedirect(route('keyring.confirm.challenge'))
            ->assertSessionHasErrors(['email' => __('keyring::keyring.sso_failed', ['provider' => 'Google'])]);
    });

    it('sends a guest who comes back to sign in', function () {
        $url = confirmAtProvider();
        Auth::logout();

        $this->get($this->google->approve($url))->assertRedirect(route('login'));
    });
});

describe('a link at a provider that can\'t be asked for a new sign in', function () {
    it('confirms with a round trip to the provider, like signing in again with it', function () {
        githubLink($this->user);
        signedInLongAgo($this->user);

        $url = confirmAtProvider();

        expect($url)->toStartWith('https://github.com/login/oauth/authorize?')
            ->and(authorizationQuery($url))->not->toHaveKeys(['max_age', 'prompt', 'claims', 'login_hint']);

        $this->get($this->github->approve($url))->assertRedirect('http://localhost/settings/danger');
        $this->get('/settings/danger')->assertOk();
        $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk();
    });

    it('is offered beside a password', function () {
        $this->user->forceFill(['password' => 'password'])->saveQuietly();
        githubLink($this->user);
        signedInLongAgo($this->user);

        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));

        $this->getJson(route('keyring.confirm.challenge'))->assertOk()->assertJsonPath('props.factor', 'password')->assertJsonPath('props.alternatives.0.factor', 'sso');
    });

    it('meets a fresh verification with a second factor, each proved on the confirm page', function () {
        githubLink($this->user);
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        signedInLongAgo($this->user);

        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect(route('keyring.confirm.challenge'));

        $url = $this->get($this->getJson(route('keyring.confirm.challenge'))->assertJsonPath('props.factor', 'sso')->json('props.challenge.url'))->headers->get('Location');

        $this->get($this->github->approve($url))->assertRedirect('http://localhost/settings/danger');
        $this->get('/settings/danger')->assertOk();
    });

    it('takes whatever auth_time an OpenID Connect provider configured not to be asked sends', function () {
        $idp = new FakeIdentityProvider()->register('fake', ['freshness' => 'round_trip']);
        Authenticator::factory()->sso('fake', '42', $idp->issuer)->for($this->user, 'authenticatable')->create();
        $idp->signIn(['sub' => '42'])->signedInAt(now()->subDay());
        signedInLongAgo($this->user);

        $url = confirmAtProvider();
        expect(authorizationQuery($url))->not->toHaveKeys(['max_age', 'prompt'])->toMatchArray(['login_hint' => 'taylor@example.com']);

        $this->get($idp->approve($url))->assertRedirect('http://localhost/settings/danger');
        $this->get('/settings/danger')->assertOk();
    });

    it('isn\'t offered when its provider can\'t be built, and the user is sent to enroll', function () {
        config(['keyring.sso.providers.github.client_id' => null]);
        $link = githubLink($this->user);
        signedInLongAgo($this->user);

        expect(Keyring::factor('sso')->confirms($link))->toBeFalse()
            ->and(Keyring::factor('sso')->reauthenticates($link))->toBeFalse();
        $this->getJson('/settings/danger')->assertForbidden()->assertJsonPath('status', 'enroll-first');

        // Nor can they add another method, as docs/sso.md says: that needs
        // a confirm, which the confirm page can't give them.
        $this->postJson(route('keyring.authenticators.store', 'totp'))->assertForbidden()->assertJsonPath('status', 'enroll-first');
    });
});

describe('a link whose sign ins are never fresh', function () {
    beforeEach(function () {
        // Google's and GitHub's defaults.
        config(['keyring.sso.providers.google.freshness' => null, 'keyring.sso.providers.github.freshness' => null]);
    });

    it('never counts a sign in as recent, whatever auth_time it brings', function (string $provider) {
        $provider === 'google' ? googleLink($this->user) : githubLink($this->user);
        $this->google->signIn(['sub' => '42'])->withClaims(['auth_time' => now()->getTimestamp()]);

        signInThrough($provider === 'google' ? $this->google : $this->github, $provider);

        $this->assertAuthenticatedAs($this->user);
        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1)
            ->and(app(SessionAssurance::class)->all()[0]->authenticatedAt)->toBe(Verification::UNKNOWN);
        $this->getJson('/settings/danger')->assertForbidden()->assertJsonPath('status', 'enroll-first');
    })->with(['google', 'github']);

    it('isn\'t offered on the confirm page beside a password', function () {
        $this->user->forceFill(['password' => 'password'])->saveQuietly();
        $link = githubLink($this->user);
        signedInLongAgo($this->user);

        // It can confirm a level, but nothing fresh.
        expect(Keyring::factor('sso')->confirms($link))->toBeTrue()
            ->and(Keyring::factor('sso')->reauthenticates($link))->toBeFalse();
        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
        $this->getJson(route('keyring.confirm.challenge'))->assertOk()->assertJsonPath('props.factor', 'password')->assertJsonPath('props.alternatives', []);
        $this->get(route('keyring.sso.confirm', ['authenticator' => $link->id]))->assertNotFound();
    });

    it('sends a user with nothing else to enroll straight away, who can\'t add a method either', function () {
        githubLink($this->user);
        signedInLongAgo($this->user);

        $this->getJson('/settings/danger')->assertForbidden()->assertJsonPath('status', 'enroll-first');
        $this->postJson(route('keyring.authenticators.store', 'totp'))->assertForbidden()->assertJsonPath('status', 'enroll-first');
        expect(app(AttemptStore::class)->current(Purpose::Confirm))->toBeNull();
    });

    it('meets a fresh verification with the second factor alone, for a user without a password', function () {
        $link = githubLink($this->user);
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        signedInLongAgo($this->user);

        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
        $this->getJson(route('keyring.confirm.challenge'))->assertOk()->assertJsonPath('props.factor', 'totp')->assertJsonPath('props.alternatives', []);
        $this->get(route('keyring.sso.confirm', ['authenticator' => $link->id]))->assertNotFound();

        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect('http://localhost/settings/danger');
        $this->get('/settings/danger')->assertOk();
        $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk();
    });

    it('still asks for the password beside the second factor when there is one', function () {
        $this->user->forceFill(['password' => 'password'])->saveQuietly();
        githubLink($this->user);
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        signedInLongAgo($this->user);

        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
        $this->getJson(route('keyring.confirm.challenge', 'totp'))->assertOk()->assertJsonPath('props.alternatives.0.factor', 'password')->assertJsonCount(1, 'props.alternatives');
        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect(route('keyring.confirm.challenge'));

        // GitHub can't stand in for the password here.
        $this->getJson(route('keyring.confirm.challenge'))->assertOk()->assertJsonPath('props.factor', 'password')->assertJsonPath('props.alternatives', []);
        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertRedirect('http://localhost/settings/danger');
        $this->get('/settings/danger')->assertOk();
    });

    it('gets a lapsed AAL2 back with a round trip to the provider and the second factor, as signing in again would', function () {
        $this->freezeSecond();
        $link = githubLink($this->user);
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        signInThrough($this->github, 'github');
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect('/dashboard');
        $this->get('/billing')->assertOk();

        // Past aal2.idle, nothing counts toward AAL2 any more.
        $this->travel(61)->minutes();
        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));

        $this->getJson(route('keyring.confirm.challenge', 'totp'))->assertOk()->assertJsonPath('props.alternatives.0.factor', 'sso');
        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect(route('keyring.confirm.challenge'));

        $url = $this->getJson(route('keyring.confirm.challenge'))->assertOk()->assertJsonPath('props.factor', 'sso')->assertJsonPath('props.alternatives', [])->json('props.challenge.url');
        $url = $this->get($url)->assertRedirect()->headers->get('Location');
        expect(authorizationQuery($url))->not->toHaveKeys(['max_age', 'prompt', 'claims']);

        $this->get($this->github->approve($url))->assertRedirect('http://localhost/billing');
        $this->get('/billing')->assertOk();

        // The round trip counts toward the level, as a sign in through
        // GitHub would, and never toward a recent verification.
        $proved = array_find(app(SessionAssurance::class)->all(), fn (Verification $verification) => $verification->authenticator === $link->id && $verification->at === now()->getTimestamp());
        expect($proved->authenticatedAt)->toBe(Verification::UNKNOWN);
    });

    it('doesn\'t satisfy password.confirm, and sends a user with nothing else to enroll from the confirm page', function () {
        Route::get('/legacy', fn () => 'legacy')->middleware(['web', 'auth', 'password.confirm:keyring.confirm.challenge']);
        githubLink($this->user);
        signedInLongAgo($this->user);

        $this->get('/legacy')->assertRedirect(route('keyring.confirm.challenge'));

        // password.confirm asks for a recent proof, and a round trip to
        // GitHub can't be one, so the bare confirm page doesn't offer it.
        $this->getJson(route('keyring.confirm.challenge'))->assertForbidden()->assertJsonPath('status', 'enroll-first');
        expect(app(AttemptStore::class)->current(Purpose::Confirm))->toBeNull();

        expect(session()->has('auth.password_confirmed_at'))->toBeFalse();
        $this->get('/legacy')->assertRedirect(route('keyring.confirm.challenge'));
    });

    it('doesn\'t satisfy password.confirm with a level confirm the round trip finishes', function () {
        Route::get('/legacy', fn () => 'legacy')->middleware(['web', 'auth', 'password.confirm:keyring.confirm.challenge']);
        githubLink($this->user);
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        // The authenticator app still counts toward AAL2, and GitHub is what's missing.
        $this->actingAs($this->user)->withSession([SessionAssurance::KEY => [$totp->id => Verification::of($totp)->toArray()]]);
        $this->travel(10)->minutes();

        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
        $url = $this->getJson(route('keyring.confirm.challenge'))->assertOk()->assertJsonPath('props.factor', 'sso')->assertJsonPath('props.alternatives', [])->json('props.challenge.url');
        $this->get($this->github->approve($this->get($url)->headers->get('Location')))->assertRedirect('http://localhost/billing');
        $this->get('/billing')->assertOk();

        // Nor does the app it built on, proved before the confirm.
        expect(session()->has('auth.password_confirmed_at'))->toBeFalse();
        $this->get('/legacy')->assertRedirect(route('keyring.confirm.challenge'));
    });

    it('takes no recovery code in place of a lost authenticator app on a fresh verification, until a password reset', function () {
        $link = githubLink($this->user);
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();
        signedInLongAgo($this->user);

        // Without the link, the app is all that's asked, and a single code
        // never freshly proves anything alone. A password reset is the way
        // out, as docs/sso.md says.
        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
        $this->getJson(route('keyring.confirm.challenge'))->assertOk()->assertJsonPath('props.factor', 'totp')->assertJsonPath('props.alternatives', []);
        $this->post(route('keyring.confirm.verify', RecoveryCodes::KEY), ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->assertSessionHasErrors();
        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));

        // As a password reset leaves them: the link gone, the app and codes kept.
        $link->delete();
        $this->user->forceFill(['password' => 'a long new passphrase'])->saveQuietly();
        signedInLongAgo($this->user->refresh());

        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'a long new passphrase'])->assertRedirect(route('keyring.confirm.challenge'));
        $this->post(route('keyring.confirm.verify', RecoveryCodes::KEY), ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->assertRedirect('http://localhost/settings/danger');
        $this->get('/settings/danger')->assertOk();
    });

    it('offers no recovery code on a fresh verification the link would have to finish', function () {
        Keyring::factors([Password::class, Totp::class, RecoveryCodes::class, WebAuthn::passkeys(), SingleSignOn::class]);
        githubLink($this->user);
        Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();
        signedInLongAgo($this->user);

        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));

        // A code beside the link would leave the confirm unfinished.
        $page = $this->getJson(route('keyring.confirm.challenge'))->assertOk();
        expect([$page->json('props.factor'), ...array_column($page->json('props.alternatives'), 'factor')])->toEqualCanonicalizing(['passkey', 'totp']);
    });

    it('asks for the level and the fresh verification in turn when a confirm can\'t give both at once', function () {
        $this->freezeSecond();
        githubLink($this->user);
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        signInThrough($this->github, 'github');
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect('/dashboard');
        $this->travel(61)->minutes();

        // As an OpenID Connect provider asked for acr_values=aal2 and max_age.
        $since = Carbon::now()->subMinutes(5);
        Route::get('/authorize', function (Request $request, StepUp $stepUp) use (&$since) {
            return $stepUp->unlessMet($request, Assurance::AAL2, $since) ?? 'authorized';
        })->middleware(['web', 'auth']);
        $meets = function () use (&$since) {
            return app(StepUp::class)->meets(request(), Assurance::AAL2, $since);
        };

        // AAL2 lapsed, so it's asked first, with a round trip and the app.
        expect($meets())->toBeFalse();
        $this->get('/authorize')->assertRedirect(route('keyring.confirm.challenge'));
        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($totp->secret, step: 1)])->assertRedirect(route('keyring.confirm.challenge'));
        $url = $this->getJson(route('keyring.confirm.challenge'))->assertOk()->assertJsonPath('props.factor', 'sso')->json('props.challenge.url');
        $this->get($this->github->approve($this->get($url)->headers->get('Location')))->assertRedirect('http://localhost/authorize');

        // The app it was reached with is fresh, so that's all.
        $this->get('/authorize')->assertOk()->assertSee('authorized');
        expect($meets())->toBeTrue();

        // Later, AAL2 still holds, and only the app is asked again.
        $this->travel(20)->minutes();
        $since = Carbon::now()->subMinutes(15);
        expect($meets())->toBeFalse();
        $this->get('/authorize')->assertRedirect(route('keyring.confirm.challenge'));
        $this->getJson(route('keyring.confirm.challenge'))->assertOk()->assertJsonPath('props.factor', 'totp')->assertJsonPath('props.alternatives', []);
        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect('http://localhost/authorize');
        $this->get('/authorize')->assertOk()->assertSee('authorized');
        expect($meets())->toBeTrue();
    });

    it('still sends a user who can give neither in turn to enroll', function () {
        githubLink($this->user);
        signedInLongAgo($this->user);

        Route::get('/authorize', fn (Request $request, StepUp $stepUp) => $stepUp->unlessMet($request, Assurance::AAL1, now()->subMinutes(5)) ?? 'authorized')->middleware(['web', 'auth']);

        expect(app(StepUp::class)->meets(request(), Assurance::AAL1, now()->subMinutes(5)))->toBeFalse();
        $this->getJson('/authorize')->assertForbidden()->assertJsonPath('status', 'enroll-first');
    });

    it('links an account as a verification that is never recent', function () {
        $this->user->forceFill(['password' => 'password'])->saveQuietly();
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subMinutes(14));

        $url = $this->postJson(route('keyring.authenticators.store', 'sso'), ['provider' => 'github'])->assertOk()->json('enrollment.url');
        $this->get($this->github->approve($url))->assertSessionHas('status', 'authenticator-added');

        $this->travel(5)->minutes();
        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
    });

    it('lets a user whose only link is never fresh out with a password reset, and link it again', function () {
        Notification::fake();
        $link = googleLink($this->user);
        $this->google->signIn(['sub' => '42']);

        signInThrough($this->google, 'google');
        $this->assertAuthenticatedAs($this->user);

        // Signed in, but nothing they have makes a protected change.
        $this->postJson(route('keyring.authenticators.store', 'totp'))->assertForbidden()->assertJsonPath('status', 'enroll-first');

        // Signed out, they ask for a reset link and choose a password.
        $this->post(route('logout'));
        $this->assertGuest();
        $this->post(route('password.email'), ['email' => 'taylor@example.com'])->assertSessionHasNoErrors();

        $token = null;
        Notification::assertSentTo($this->user, ResetPassword::class, function (ResetPassword $notice) use (&$token) {
            $token = $notice->token;

            return true;
        });

        $this->post(route('password.update'), [
            'token' => $token,
            'email' => 'taylor@example.com',
            'password' => 'a long new passphrase',
            'password_confirmation' => 'a long new passphrase',
        ])->assertRedirect(route('login'));

        // The reset unlinked Google, as it unlinks every provider.
        expect(Authenticator::find($link->id))->toBeNull();

        // The password signs them in fresh, so they can add a method and
        // link Google again.
        $this->post(route('login.store'), ['email' => 'taylor@example.com', 'password' => 'a long new passphrase'])->assertRedirect('/dashboard');
        $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk();

        $url = $this->postJson(route('keyring.authenticators.store', 'sso'), ['provider' => 'google'])->assertOk()->json('enrollment.url');
        $this->get($this->google->approve($url))->assertSessionHas('status', 'authenticator-added');
        expect($this->user->keyring->refresh()->of('sso'))->toHaveCount(1);
    });
});

describe('Microsoft without the auth_time optional claim', function () {
    beforeEach(function () {
        $this->microsoft = FakeIdentityProvider::microsoft()->register('microsoft');
        reloadRoutes();
        protectedPages();
        $this->link = Authenticator::factory()->sso('microsoft', '42', $this->microsoft->tokenIssuer())->for($this->user, 'authenticatable')->create();
        $this->microsoft->signIn(['sub' => '42']);
    });

    it('never counts a sign in as recent', function () {
        signInThrough($this->microsoft, 'microsoft');

        $this->assertAuthenticatedAs($this->user);
        expect(app(SessionAssurance::class)->all()[0]->authenticatedAt)->toBe(Verification::UNKNOWN);
        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
    });

    it('fails a confirm, and reports what to add to the app registration', function () {
        Exceptions::fake();
        signedInLongAgo($this->user);

        $this->get($this->microsoft->approve(confirmAtProvider()))
            ->assertRedirect(route('keyring.confirm.challenge'))
            ->assertSessionHasErrors(['email' => __('keyring::keyring.sso_failed', ['provider' => 'Microsoft'])]);

        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
        Exceptions::assertReported(fn (SsoFailed $e) => $e->reason === SsoFailure::StaleAuthentication
            && str_contains($e->getMessage(), 'Token configuration, Add optional claim, choose the ID token type and tick auth_time')
            && str_contains($e->getMessage(), 'optionalClaims.idToken')
            && str_contains($e->getMessage(), 'https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims'));
    });

    it('confirms once the claim is there', function () {
        signedInLongAgo($this->user);
        $this->microsoft->withAuthTimeClaim();

        $this->get($this->microsoft->approve(confirmAtProvider()))->assertRedirect('http://localhost/settings/danger');
        $this->get('/settings/danger')->assertOk();
    });
});

describe('providers configured after the routes', function () {
    beforeEach(function () {
        config(['keyring.sso.providers' => []]);
        reloadRoutes();
        protectedPages();
        FakeIdentityProvider::google()->register('google');
    });

    it('offers no buttons on the login page', function () {
        expect(Route::has('keyring.sso.redirect'))->toBeFalse()
            ->and(Keyring::factor('sso')->providers())->toBe([]);

        $this->getJson(route('login'))->assertOk()->assertJsonPath('props.providers', []);
    });

    it('refuses to start a link, with nowhere for the provider to send the user back to', function () {
        $this->user->forceFill(['password' => 'password'])->saveQuietly();
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now());

        expect(Route::has('keyring.sso.callback'))->toBeFalse();
        $this->postJson(route('keyring.authenticators.store', 'sso'), ['provider' => 'google'])->assertJsonValidationErrors('provider');
    });

    it('offers no link on the confirm page', function () {
        $this->user->forceFill(['password' => 'password'])->saveQuietly();
        $link = googleLink($this->user);
        signedInLongAgo($this->user);

        expect(Keyring::factor('sso')->confirms($link))->toBeFalse();
        $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
        $this->getJson(route('keyring.confirm.challenge'))->assertOk()->assertJsonPath('props.factor', 'password')->assertJsonPath('props.alternatives', []);
    });
});

describe('a frontend Laravel does not serve', function () {
    beforeEach(function () {
        $this->link = googleLink($this->user);
        signedInLongAgo($this->user);
        $this->get('/settings/danger');
    });

    it('gets the url to send the user to', function () {
        expect($this->getJson(route('keyring.sso.confirm'))->assertOk()->json('url'))->toStartWith('https://accounts.google.com/');
    });

    it('has an inertia visit load the provider in full', function () {
        $response = $this->inertia()->get(route('keyring.sso.confirm'))->assertStatus(409);

        expect($response->headers->get('X-Inertia-Location'))->toStartWith('https://accounts.google.com/');
    });

    it('passes the callback on and gets the answer as json', function () {
        $url = $this->getJson(route('keyring.sso.confirm'))->json('url');

        $this->getJson($this->google->signIn(['sub' => '42'])->approve($url))
            ->assertOk()
            ->assertExactJson(['status' => 'authenticated', 'redirect' => 'http://localhost/settings/danger']);
    });

    it('gets refusals as validation errors', function () {
        $url = $this->getJson(route('keyring.sso.confirm'))->json('url');

        $this->getJson($this->google->signIn(['sub' => '43'])->approve($url))->assertUnprocessable()->assertJsonValidationErrors(['email' => __('keyring::keyring.invalid')]);

        app(AttemptStore::class)->forget(Purpose::Confirm);
        $this->getJson(route('keyring.sso.confirm'))->assertUnprocessable()->assertJsonValidationErrors(['email' => __('keyring::keyring.expired')]);
    });
});

describe('the factor', function () {
    function confirmIdentity(Attempt $attempt, Authenticator $link, array $data = [], ?int $maxAge = 0, string $purpose = SingleSignOn::CONFIRM): Identity
    {
        $request = AuthorizationRequest::make($link->meta('provider'), $purpose, SSO_CALLBACK, [
            'user' => (string) $attempt->userId,
            'attempt' => $attempt->id,
            'authenticator' => $link->id,
            ...$data,
        ], $maxAge);

        return new Identity($request, $link->meta('provider'), $link->meta('issuer'), $link->meta('subject'), 'taylor@example.com', true, authTime: now()->getTimestamp());
    }

    it('confirms only with an identity from a confirm started for the attempt\'s user and link', function (string $provider, Closure $identity, bool $confirms) {
        $link = $provider === 'google' ? googleLink($this->user) : githubLink($this->user);
        $attempt = Attempt::start(Purpose::Confirm, $this->user, requirement: Requirement::aal1());
        $request = Request::create('/');
        $request->attributes->set(SingleSignOn::IDENTITY, $identity($attempt, $link));

        expect(Keyring::factor('sso')->verify($attempt, $link, $request) !== null)->toBe($confirms);
    })->with([
        'as started' => ['google', fn ($attempt, $link) => confirmIdentity($attempt, $link), true],
        'to sign in' => ['google', fn ($attempt, $link) => confirmIdentity($attempt, $link, purpose: SingleSignOn::LOGIN), false],
        'without asking for a new sign in' => ['google', fn ($attempt, $link) => confirmIdentity($attempt, $link, maxAge: null), false],
        'for another user' => ['google', fn ($attempt, $link) => confirmIdentity($attempt, $link, ['user' => '999']), false],
        'for another link' => ['google', fn ($attempt, $link) => confirmIdentity($attempt, $link, ['authenticator' => 'other']), false],
        'at a provider that can\'t be asked' => ['github', fn ($attempt, $link) => confirmIdentity($attempt, $link, maxAge: null), true],
    ]);

    it('stamps a sign in with when the provider says it was when either the link\'s provider or the one it came through can be asked', function (string $stored, string $through, bool $stamped, string $kept) {
        $this->freezeSecond();
        $link = Authenticator::factory()->sso($stored, '42', GoogleProvider::ISSUER)->for($this->user, 'authenticatable')->create();
        $request = Request::create('/');
        $request->attributes->set(SingleSignOn::IDENTITY, new Identity(AuthorizationRequest::make($through, SingleSignOn::LOGIN, SSO_CALLBACK), $through, GoogleProvider::ISSUER, '42', authTime: now()->subHour()->getTimestamp()));

        $verification = Keyring::factor('sso')->verify(Attempt::start(Purpose::Login, $this->user), $link, $request);

        expect($verification->authenticatedAt)->toBe($stamped ? now()->subHour()->getTimestamp() : null)
            ->and($link->meta('provider'))->toBe($kept);
    })->with([
        // The link keeps its provider while that's configured, and takes
        // the one it came through once it isn't.
        'stored can be asked' => ['google', 'github', true, 'google'],
        'came through one that can be asked' => ['github', 'google', true, 'github'],
        'removed, came through one that can be asked' => ['gone', 'google', true, 'google'],
        'neither' => ['gone', 'github', false, 'github'],
    ]);

    it('goes by the strictest of the link\'s provider and the one it came through, so a rename or removal loosens nothing', function (string $stored, string $through, string $signIn, string|false $confirm) {
        $this->freezeSecond();
        $idp = new FakeIdentityProvider;
        $idp->register('reauthenticates');
        $idp->register('round-trip', ['freshness' => 'round_trip']);
        $idp->register('never', ['freshness' => 'never']);
        $link = Authenticator::factory()->sso($stored, '42', $idp->issuer)->for($this->user, 'authenticatable')->create();
        $identity = fn (string $purpose, ?int $maxAge) => new Identity(AuthorizationRequest::make($through, $purpose, SSO_CALLBACK, [
            'user' => (string) $this->user->id,
            'authenticator' => $link->id,
        ], $maxAge), $through, $idp->issuer, '42', authTime: now()->subHour()->getTimestamp());

        $request = Request::create('/');
        $request->attributes->set(SingleSignOn::IDENTITY, $identity(SingleSignOn::LOGIN, null));
        $verification = Keyring::factor('sso')->verify(Attempt::start(Purpose::Login, $this->user), $link, $request);

        expect($verification->authenticatedAt)->toBe(match ($signIn) {
            'now' => null,
            'auth_time' => now()->subHour()->getTimestamp(),
            'never' => Verification::UNKNOWN,
        });

        // A confirm, started as the link's provider says: a new sign in
        // when it reauthenticates, a round trip otherwise. One that's never
        // fresh confirms toward a level alone, as signing in again would.
        $link->forceFill(['meta' => [...$link->meta, 'provider' => $stored]]);
        $attempt = Attempt::start(Purpose::Confirm, $this->user, requirement: Requirement::aal1());
        $request->attributes->set(SingleSignOn::IDENTITY, $identity(SingleSignOn::CONFIRM, Keyring::factor('sso')->reauthenticates($link) ? 0 : null));

        $confirmed = Keyring::factor('sso')->verify($attempt, $link, $request);

        expect($confirmed?->authenticatedAt)->toBe(match ($confirm) {
            false, 'now' => null,
            'never' => Verification::UNKNOWN,
        })->and($confirmed !== null)->toBe($confirm !== false);
    })->with([
        'reauthenticates' => ['reauthenticates', 'reauthenticates', 'auth_time', 'now'],
        'a round trip' => ['round-trip', 'round-trip', 'now', 'now'],
        'never' => ['never', 'never', 'never', 'never'],
        'made with one that reauthenticates, came through a round trip' => ['reauthenticates', 'round-trip', 'auth_time', 'now'],
        'made with a round trip, came through one that reauthenticates' => ['round-trip', 'reauthenticates', 'auth_time', false],
        'made with never, came through a round trip' => ['never', 'round-trip', 'never', 'never'],
        'made with a round trip, came through never' => ['round-trip', 'never', 'never', 'never'],
        'made with never, came through one that reauthenticates' => ['never', 'reauthenticates', 'never', 'never'],
        'removed, came through a round trip' => ['gone', 'round-trip', 'now', 'now'],
        'removed, came through one that reauthenticates' => ['gone', 'reauthenticates', 'auth_time', false],
        'removed, came through never' => ['gone', 'never', 'never', 'never'],
        'neither configured' => ['gone', 'also gone', 'never', 'never'],
    ]);

    it('keeps going by the stricter provider however many sign ins come through the looser one', function () {
        $this->freezeSecond();
        $idp = new FakeIdentityProvider;
        $idp->register('reauthenticates');
        $idp->register('round-trip', ['freshness' => 'round_trip']);
        $link = Authenticator::factory()->sso('reauthenticates', '42', $idp->issuer)->for($this->user, 'authenticatable')->create();
        $idp->signIn(['sub' => '42'])->signedInAt(now()->subHour());

        foreach ([1, 2] as $time) {
            signInThrough($idp, 'round-trip');
            $this->assertAuthenticatedAs($this->user);

            expect(app(SessionAssurance::class)->all()[0]->authenticatedAt)->toBe(now()->subHour()->getTimestamp())
                ->and($link->fresh()->meta('provider'))->toBe('reauthenticates');

            $this->post(route('logout'));
        }
    });

    it('stamps a sign in with when the provider says it was, and a confirm with now', function () {
        $link = googleLink($this->user);
        $request = Request::create('/');
        $request->attributes->set(SingleSignOn::IDENTITY, new Identity(AuthorizationRequest::make('google', SingleSignOn::LOGIN, SSO_CALLBACK), 'google', GoogleProvider::ISSUER, '42', authTime: now()->subHour()->getTimestamp()));

        $verification = Keyring::factor('sso')->verify(Attempt::start(Purpose::Login, $this->user), $link, $request);

        expect($verification->at)->toBe(now()->getTimestamp())
            ->and($verification->authenticatedAt)->toBe(now()->subHour()->getTimestamp())
            ->and($verification->provedAt())->toBe(now()->subHour()->getTimestamp())
            ->and($verification->toArray()['authenticated_at'])->toBe(now()->subHour()->getTimestamp());

        $attempt = Attempt::start(Purpose::Confirm, $this->user, requirement: Requirement::aal1());
        $request->attributes->set(SingleSignOn::IDENTITY, confirmIdentity($attempt, $link));

        expect(Keyring::factor('sso')->verify($attempt, $link, $request)->authenticatedAt)->toBeNull();
    });
});

describe('asking a provider for a new sign in', function () {
    it('sends max_age, with prompt=login only for 0', function () {
        new FakeIdentityProvider()->register('fake');

        expect(authorizationQuery(Keyring::sso()->start('fake', 'step-up', SSO_CALLBACK, maxAge: 300)))->toMatchArray(['max_age' => '300'])->not->toHaveKey('prompt')
            ->and(authorizationQuery(Keyring::sso()->start('fake', 'step-up', SSO_CALLBACK, maxAge: 0)))->toMatchArray(['max_age' => '0', 'prompt' => 'login']);
    });

    it('sends Microsoft max_age for any age but 0', function () {
        FakeIdentityProvider::microsoft()->register('fake');

        expect(authorizationQuery(Keyring::sso()->start('fake', 'step-up', SSO_CALLBACK, maxAge: 300)))->toMatchArray(['max_age' => '300'])->not->toHaveKey('prompt');
    });

    it('sends a login_hint to an OpenID Connect provider, and none to GitHub', function () {
        new FakeIdentityProvider()->register('fake');

        expect(authorizationQuery(Keyring::sso()->start('fake', 'login', SSO_CALLBACK, loginHint: 'taylor@example.com')))->toMatchArray(['login_hint' => 'taylor@example.com'])
            ->and(authorizationQuery(Keyring::sso()->start('github', 'login', SSO_CALLBACK, loginHint: 'taylor@example.com')))->not->toHaveKey('login_hint');
    });

    it('keeps max_age, when it was made and the login_hint with the request', function () {
        $request = AuthorizationRequest::make('fake', 'step-up', SSO_CALLBACK, maxAge: 300, loginHint: 'taylor@example.com');
        $kept = AuthorizationRequest::fromArray($request->toArray());

        expect($kept->maxAge)->toBe(300)
            ->and($kept->createdAt)->toBe(now()->getTimestamp())
            ->and($kept->loginHint)->toBe('taylor@example.com')
            ->and(AuthorizationRequest::fromArray(AuthorizationRequest::make('fake', 'login', SSO_CALLBACK)->toArray())->maxAge)->toBeNull();
    });

    it('takes a session within max_age of the request, and asks for a new sign in past it', function () {
        $idp = new FakeIdentityProvider()->register('fake')->signedInAt(now()->subMinutes(2));

        expect(ssoComplete($idp->approve(Keyring::sso()->start('fake', 'step-up', SSO_CALLBACK, maxAge: 300)))->authTime)->toBe(now()->subMinutes(2)->getTimestamp())
            ->and(ssoComplete($idp->approve(Keyring::sso()->start('fake', 'step-up', SSO_CALLBACK, maxAge: 60)))->authTime)->toBe(now()->getTimestamp());
    });

    it('measures max_age from when the user was sent, not when they came back', function () {
        $idp = new FakeIdentityProvider()->register('fake')->ignoringReauthentication()->signedInAt(now()->subMinutes(4));
        $url = Keyring::sso()->start('fake', 'step-up', SSO_CALLBACK, maxAge: 300);
        $callback = $idp->approve($url);

        $this->travel(5)->minutes();

        expect(ssoComplete($callback)->authTime)->toBe(now()->subMinutes(9)->getTimestamp());
    });

    it('can\'t ask a provider that can\'t be asked', function (string $provider, int $maxAge) {
        new FakeIdentityProvider()->register('fake');

        expect(fn () => Keyring::sso()->start($provider, 'step-up', SSO_CALLBACK, maxAge: $maxAge))
            ->toThrow(InvalidArgumentException::class, "Identity provider [{$provider}] can't be asked for a sign in no older than [{$maxAge}] seconds.");
    })->with([['github', 0], ['fake', -1]]);

    it('says which providers can be asked, and how fresh each driver\'s sign ins are by default', function (string $driver, ?string $freshness, bool $asks, SsoFreshness $expected) {
        $idp = match ($driver) {
            'oidc' => new FakeIdentityProvider,
            'google' => FakeIdentityProvider::google(),
            'microsoft' => FakeIdentityProvider::microsoft(),
            'github' => FakeIdentityProvider::github(),
        };
        $idp->register('preset', $freshness === null ? [] : ['freshness' => $freshness]);

        expect(Keyring::sso()->provider('preset')->supportsReauthentication())->toBe($asks)
            ->and(Keyring::sso()->provider('preset')->freshness())->toBe($expected);
    })->with([
        'oidc' => ['oidc', null, true, SsoFreshness::Reauthenticate],
        'oidc, a round trip' => ['oidc', 'round_trip', true, SsoFreshness::RoundTrip],
        'oidc, never' => ['oidc', 'never', true, SsoFreshness::Never],
        'google' => ['google', null, true, SsoFreshness::Never],
        'google, set up for it' => ['google', 'reauthenticate', true, SsoFreshness::Reauthenticate],
        'microsoft' => ['microsoft', null, true, SsoFreshness::Reauthenticate],
        'microsoft, never' => ['microsoft', 'never', true, SsoFreshness::Never],
        'github' => ['github', null, false, SsoFreshness::Never],
        'github, a round trip' => ['github', 'round_trip', false, SsoFreshness::RoundTrip],
    ]);

    it('takes false for never', function () {
        new FakeIdentityProvider()->register('fake', ['freshness' => false]);

        expect(Keyring::sso()->provider('fake')->freshness())->toBe(SsoFreshness::Never);
    });

    it('refuses a freshness it doesn\'t know', function (mixed $freshness) {
        new FakeIdentityProvider()->register('fake', ['freshness' => $freshness]);

        expect(fn () => Keyring::sso()->provider('fake'))
            ->toThrow(InvalidArgumentException::class, 'Identity provider [fake] has a "freshness" that isn\'t reauthenticate, round_trip or never.');
    })->with(['roundtrip', true, 1]);

    it('refuses to have a provider that can\'t be asked reauthenticate', function () {
        FakeIdentityProvider::github()->register('github', ['freshness' => 'reauthenticate']);

        expect(fn () => Keyring::sso()->provider('github'))
            ->toThrow(InvalidArgumentException::class, 'Identity provider [github] can\'t be asked for a new sign in, so its "freshness" can\'t be reauthenticate.')
            ->and(Keyring::sso()->providers()->keys()->all())->toBe(['google']);
    });

    it('asks for auth_time with a request that has a maxAge, whatever the provider\'s freshness', function () {
        config(['keyring.sso.providers.google.freshness' => 'never']);

        expect(authorizationQuery(Keyring::sso()->start('google', 'step-up', SSO_CALLBACK, maxAge: 300)))->toMatchArray(['claims' => '{"id_token":{"auth_time":{"essential":true}}}', 'max_age' => '300'])
            ->and(authorizationQuery(Keyring::sso()->start('google', 'login', SSO_CALLBACK)))->not->toHaveKey('claims');
    });

    it('has the fake provider refuse what the real one would', function (string $query, string $problem) {
        $url = Keyring::sso()->start('google', 'login', SSO_CALLBACK);

        expect(fn () => $this->google->approve($url.$query))->toThrow(InvalidArgumentException::class, $problem);
    })->with([
        'prompt=login at Google' => ['&prompt=login', 'Google takes no prompt=login'],
        'a max_age that is no number' => ['&max_age=soon', 'its max_age is not a number of seconds'],
    ]);
});
