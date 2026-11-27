<?php

declare(strict_types=1);

use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Keyring\Contracts\IdentityProvider;
use Keyring\Enums\SsoFailure;
use Keyring\Enums\SsoFreshness;
use Keyring\Exceptions\UnknownSsoProvider;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\SingleSignOn;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Sso\AuthorizationRequest;
use Keyring\Sso\Identity;
use Keyring\Sso\Providers\GitHubProvider;
use Keyring\Sso\Providers\GoogleProvider;
use Keyring\Sso\Providers\MicrosoftProvider;
use Keyring\Sso\Providers\OidcProvider;
use Keyring\Testing\FakeIdentityProvider;

// Nothing here may reach a real provider.
beforeEach(fn () => Http::preventStrayRequests());

const CONTOSO = '0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0';

// Google

it('signs in with Google, whichever way its tokens name the issuer', function (string $issuer) {
    $idp = FakeIdentityProvider::google()->register('google', ['issuer' => 'https://evil.test']);

    $identity = ssoComplete($idp->withClaims(['iss' => $issuer])->approve(ssoStart('google')), 'google');

    expect($identity->issuer)->toBe(GoogleProvider::ISSUER)
        ->and($identity->emailVerified)->toBeTrue()
        ->and(Keyring::sso()->provider('google')->label())->toBe('Google');
})->with(['https://accounts.google.com', 'accounts.google.com']);

it('refuses a Google token from another issuer', function () {
    $idp = FakeIdentityProvider::google()->register('google');

    expect(ssoFailure(fn () => ssoComplete($idp->withClaims(['iss' => 'https://accounts.google.com.evil.test'])->approve(ssoStart('google')), 'google'))[0])->toBe(SsoFailure::InvalidToken);
});

// Microsoft

it('signs in with Microsoft on a multi-tenant endpoint, as the user\'s own tenant', function (string $tenant) {
    $idp = FakeIdentityProvider::microsoft(strtolower($tenant), CONTOSO)->register('microsoft', ['tenant' => $tenant]);

    $identity = ssoComplete($idp->approve(ssoStart('microsoft')), 'microsoft');

    expect($identity->issuer)->toBe('https://login.microsoftonline.com/'.CONTOSO.'/v2.0')
        ->and($identity->claims['tid'])->toBe(CONTOSO)
        ->and(Keyring::sso()->provider('microsoft')->label())->toBe('Microsoft')
        ->and(authorizationQuery(ssoStart('microsoft')))->not->toHaveKey('response_mode');
})->with(['common', 'organizations', 'COMMON']);

it('refuses a Microsoft token whose issuer isn\'t its own tenant\'s', function (array $claims) {
    $idp = FakeIdentityProvider::microsoft('common', CONTOSO)->register('microsoft');

    expect(ssoFailure(fn () => ssoComplete($idp->withClaims($claims)->approve(ssoStart('microsoft')), 'microsoft')))
        ->toBe([SsoFailure::InvalidToken, 'Single sign-on failed (invalid_token): [microsoft]: The ID token is from another issuer.']);
})->with([
    'another tenant\'s issuer' => [['iss' => 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0']],
    'another tenant\'s tid' => [['tid' => '11111111-2222-3333-4444-555555555555']],
    'the template itself' => [['iss' => 'https://login.microsoftonline.com/{tenantid}/v2.0']],
    'a tid that isn\'t an ID' => [['tid' => '../evil', 'iss' => 'https://login.microsoftonline.com/../evil/v2.0']],
    'no tid' => [['tid' => null]],
]);

it('keeps personal Microsoft accounts out of "organizations", and lets them into "common"', function () {
    $idp = FakeIdentityProvider::microsoft('organizations', MicrosoftProvider::CONSUMERS)->register('microsoft', ['tenant' => 'organizations']);

    expect(ssoFailure(fn () => ssoComplete($idp->approve(ssoStart('microsoft')), 'microsoft')))
        ->toBe([SsoFailure::InvalidToken, 'Single sign-on failed (invalid_token): [microsoft]: The ID token is from another issuer.']);

    $idp = FakeIdentityProvider::microsoft('common', MicrosoftProvider::CONSUMERS)->register('microsoft', ['tenant' => 'common']);

    expect(ssoComplete($idp->approve(ssoStart('microsoft')), 'microsoft')->issuer)->toBe('https://login.microsoftonline.com/'.MicrosoftProvider::CONSUMERS.'/v2.0');
});

it('signs in personal Microsoft accounts on the consumers endpoint', function () {
    $idp = FakeIdentityProvider::microsoft('consumers')->register('microsoft', ['tenant' => 'consumers']);

    expect(ssoComplete($idp->approve(ssoStart('microsoft')), 'microsoft')->issuer)->toBe('https://login.microsoftonline.com/'.MicrosoftProvider::CONSUMERS.'/v2.0');
});

it('signs in one tenant\'s accounts, by its ID or its domain', function (string $tenant) {
    $idp = FakeIdentityProvider::microsoft($tenant, CONTOSO)->register('microsoft');

    expect(ssoComplete($idp->approve(ssoStart('microsoft')), 'microsoft')->issuer)->toBe('https://login.microsoftonline.com/'.CONTOSO.'/v2.0');

    expect(ssoFailure(fn () => ssoComplete($idp->withClaims(['iss' => 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0'])->approve(ssoStart('microsoft')), 'microsoft'))[0])
        ->toBe(SsoFailure::InvalidToken);
})->with([CONTOSO, 'contoso.onmicrosoft.com']);

it('refuses Microsoft discovery for another issuer than the tenant\'s', function (string $tenant, string $issuer) {
    $idp = FakeIdentityProvider::microsoft($tenant, CONTOSO)->register('microsoft');
    $idp->withDiscovery(['issuer' => $issuer]);

    expect(ssoFailure(fn () => ssoStart('microsoft'))[0])->toBe(SsoFailure::Unavailable);
})->with([
    'a tenant ID, for another tenant' => [CONTOSO, 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0'],
    'a domain, off Microsoft\'s host' => ['contoso.onmicrosoft.com', 'https://evil.test/'.CONTOSO.'/v2.0'],
    'common, for one tenant' => ['common', 'https://login.microsoftonline.com/'.CONTOSO.'/v2.0'],
    'consumers, for another tenant' => ['consumers', 'https://login.microsoftonline.com/'.CONTOSO.'/v2.0'],
]);

it('refuses a tenant that can\'t be part of a URL', function () {
    config(['keyring.sso.providers.microsoft' => ['driver' => 'microsoft', 'client_id' => 'x', 'tenant' => '../common']]);

    Keyring::sso()->provider('microsoft');
})->throws(InvalidArgumentException::class, 'invalid tenant');

it('never takes a Microsoft address as verified, unless the tenant verified its domain', function () {
    $idp = FakeIdentityProvider::microsoft()->register('microsoft');

    expect(ssoComplete($idp->approve(ssoStart('microsoft')), 'microsoft')->emailVerified)->toBeFalse()
        ->and(ssoComplete($idp->withClaims(['xms_edov' => 1])->approve(ssoStart('microsoft')), 'microsoft')->emailVerified)->toBeFalse()
        ->and(ssoComplete($idp->withClaims(['xms_edov' => true])->approve(ssoStart('microsoft')), 'microsoft')->emailVerified)->toBeTrue();
});

it('holds a Microsoft callback\'s iss to the token\'s tenant', function () {
    $idp = FakeIdentityProvider::microsoft('common', CONTOSO)->sendsIssuer()->register('microsoft');

    expect(ssoComplete($idp->approve(ssoStart('microsoft')), 'microsoft')->issuer)->toBe('https://login.microsoftonline.com/'.CONTOSO.'/v2.0');

    $other = str_replace(CONTOSO, '11111111-2222-3333-4444-555555555555', $idp->approve(ssoStart('microsoft')));

    expect(ssoFailure(fn () => ssoComplete($other, 'microsoft')))->toBe([SsoFailure::InvalidResponse, 'Single sign-on failed (invalid_response): The callback for [microsoft] came from another issuer.']);

    $offHost = str_replace('login.microsoftonline.com', 'evil.test', $idp->approve(ssoStart('microsoft')));

    expect(ssoFailure(fn () => ssoComplete($offHost, 'microsoft'))[0])->toBe(SsoFailure::InvalidResponse);
});

it('holds a single tenant\'s callback iss to that tenant before the code is sent anywhere', function () {
    $idp = FakeIdentityProvider::microsoft(CONTOSO)->sendsIssuer()->register('microsoft');

    $other = str_replace(CONTOSO.'%2Fv2.0', '11111111-2222-3333-4444-555555555555%2Fv2.0', $idp->approve(ssoStart('microsoft')));

    expect(ssoFailure(fn () => ssoComplete($other, 'microsoft'))[0])->toBe(SsoFailure::InvalidResponse);

    Http::assertNotSent(fn (ClientRequest $request) => str_ends_with($request->url(), '/token'));
});

// GitHub

it('signs in with GitHub as its numeric ID, with its verified primary address', function () {
    $idp = FakeIdentityProvider::github()->register('github');

    $url = ssoStart('github');
    $identity = ssoComplete($idp->approve($url), 'github');

    expect($url)->toStartWith('https://github.com/login/oauth/authorize?')
        ->and(authorizationQuery($url))->toMatchArray(['scope' => 'read:user user:email', 'code_challenge_method' => 'S256'])
        ->and(authorizationQuery($url))->not->toHaveKey('nonce')
        ->and($identity->issuer)->toBe('https://github.com')
        ->and($identity->subject)->toBe('583231')
        ->and($identity->email)->toBe('taylor@example.com')
        ->and($identity->emailVerified)->toBeTrue()
        ->and($identity->name)->toBe('Taylor Otwell')
        ->and($identity->claims['login'])->toBe('taylor')
        ->and(Keyring::sso()->provider('github')->label())->toBe('GitHub');

    Http::assertSent(fn (ClientRequest $request) => $request->url() === 'https://github.com/login/oauth/access_token'
        && $request['client_secret'] === FakeIdentityProvider::CLIENT_SECRET
        && is_string($request['code_verifier']));

    Http::assertSent(fn (ClientRequest $request) => $request->url() === 'https://api.github.com/user'
        && $request->header('X-GitHub-Api-Version') === ['2022-11-28']);
});

it('takes a GitHub address as verified only when it\'s the primary one and verified', function () {
    $idp = FakeIdentityProvider::github()->register('github');

    $identity = ssoComplete($idp->signIn([], [
        ['email' => 'old@example.com', 'primary' => false, 'verified' => true],
        ['email' => 'taylor@example.com', 'primary' => true, 'verified' => false],
        'junk',
    ])->approve(ssoStart('github')), 'github');

    expect($identity->email)->toBe('taylor@example.com')->and($identity->emailVerified)->toBeFalse();
});

it('keeps GitHub\'s public address unverified without the user:email scope', function () {
    $idp = FakeIdentityProvider::github()->register('github', ['scopes' => ['read:user']]);

    $identity = ssoComplete($idp->signIn(['email' => 'public@example.com', 'name' => null])->approve(ssoStart('github')), 'github');

    expect($identity->email)->toBe('public@example.com')
        ->and($identity->emailVerified)->toBeFalse()
        ->and($identity->name)->toBe('taylor');

    Http::assertNotSent(fn (ClientRequest $request) => $request->url() === 'https://api.github.com/user/emails');
});

it('refuses a GitHub sign in it can\'t read the account of', function (Closure $break, SsoFailure $reason) {
    $idp = FakeIdentityProvider::github()->register('github');
    $url = ssoStart('github');
    $break($idp);

    expect(ssoFailure(fn () => ssoComplete($idp->approve($url), 'github'))[0])->toBe($reason);
})->with([
    'a refused code' => [fn (FakeIdentityProvider $idp) => $idp->failExchange(), SsoFailure::ExchangeFailed],
    'the API down' => [fn (FakeIdentityProvider $idp) => $idp->down(), SsoFailure::Unavailable],
    'no ID' => [fn (FakeIdentityProvider $idp) => $idp->signIn(['id' => null]), SsoFailure::Unavailable],
    'an ID that is a string' => [fn (FakeIdentityProvider $idp) => $idp->signIn(['id' => '583231']), SsoFailure::Unavailable],
]);

it('refuses a GitHub API answer that isn\'t JSON', function () {
    Http::fake(['https://api.github.com/user' => Http::response('<html>', 200)]);
    $idp = FakeIdentityProvider::github()->register('github');

    expect(ssoFailure(fn () => ssoComplete($idp->approve(ssoStart('github')), 'github')))
        ->toBe([SsoFailure::Unavailable, 'Single sign-on failed (unavailable): [github]\'s API did not answer with JSON at [/user].']);
});

it('answers GitHub\'s API only for a token it handed out', function () {
    FakeIdentityProvider::github();

    expect(Http::withToken('made-up')->get('https://api.github.com/user')->status())->toBe(401);
});

// The providers

it('lists the configured providers, by name', function () {
    FakeIdentityProvider::google()->register('google');
    new FakeIdentityProvider()->register('acme', ['name' => 'Acme SSO']);
    new FakeIdentityProvider('https://login.example-corp.test')->register('example_corp');

    $providers = Keyring::sso()->providers();

    expect($providers->keys()->all())->toBe(['google', 'acme', 'example_corp'])
        ->and($providers->map->label()->all())->toBe(['google' => 'Google', 'acme' => 'Acme SSO', 'example_corp' => 'Example Corp'])
        ->and(Keyring::sso()->has('acme'))->toBeTrue()
        ->and(Keyring::sso()->has('missing'))->toBeFalse();

    config(['keyring.sso.providers' => null]);

    expect(Keyring::sso()->providers())->toBeEmpty();
});

it('answers an unknown provider with a 404', function () {
    try {
        Keyring::sso()->provider('missing');
    } catch (UnknownSsoProvider $e) {
        expect($e->getStatusCode())->toBe(404)->and($e->getHeaders())->toBe([]);

        return;
    }

    $this->fail('No exception was thrown.');
});

it('refuses a provider it can\'t build', function (array $config, string $message) {
    config(['keyring.sso.providers.broken' => $config]);

    expect(fn () => Keyring::sso()->provider('broken'))->toThrow(InvalidArgumentException::class, $message);
})->with([
    'no driver' => [['client_id' => 'x'], 'has no driver Keyring knows'],
    'an unknown driver' => [['driver' => 'saml', 'client_id' => 'x'], 'has no driver Keyring knows'],
    'no client ID' => [['driver' => 'google'], 'needs a client_id'],
    'an empty client ID' => [['driver' => 'github', 'client_id' => ''], 'needs a client_id'],
    'no issuer' => [['driver' => 'oidc', 'client_id' => 'x'], 'needs an HTTPS issuer'],
    'a plain HTTP issuer' => [['driver' => 'oidc', 'client_id' => 'x', 'issuer' => 'http://idp.test'], 'needs an HTTPS issuer'],
    'a parameter Keyring sends' => [['driver' => 'github', 'client_id' => 'x', 'parameters' => ['state' => 'fixed']], 'can\'t set the [state] parameter'],
    'max_age' => [['driver' => 'google', 'client_id' => 'x', 'parameters' => ['max_age' => 0]], 'can\'t set the [max_age] parameter'],
]);

it('takes a provider run on this machine over plain HTTP', function () {
    config(['keyring.sso.providers.keycloak' => ['driver' => 'oidc', 'client_id' => 'x', 'issuer' => 'http://localhost:8080/realms/app']]);

    expect(Keyring::sso()->provider('keycloak'))->toBeInstanceOf(OidcProvider::class)
        ->and(Keyring::sso()->provider('keycloak')->issuer())->toBe('http://localhost:8080/realms/app');
});

it('ignores parameters and scopes that aren\'t lists of what they should be', function () {
    $idp = new FakeIdentityProvider()->register(config: ['parameters' => 'prompt=none', 'scopes' => ['email', 42]]);

    expect(authorizationQuery(ssoStart())['scope'])->toBe('openid email')
        ->and(authorizationQuery(ssoStart()))->not->toHaveKey('prompt');
});

it('builds providers with a driver the app registered', function () {
    config(['keyring.sso.providers.corp' => ['driver' => 'corp', 'client_id' => 'x', 'realm' => 'staff']]);

    $provider = new readonly class('corp') implements IdentityProvider
    {
        public function __construct(private string $name, private SsoFreshness $freshness = SsoFreshness::Never) {}

        public function name(): string
        {
            return $this->name;
        }

        public function label(): string
        {
            return 'Corp';
        }

        public function supportsReauthentication(): bool
        {
            return false;
        }

        public function freshness(): SsoFreshness
        {
            return $this->freshness;
        }

        public function authorizationUrl(AuthorizationRequest $request): string
        {
            return 'https://corp.test/login?state='.$request->state;
        }

        public function identify(AuthorizationRequest $request, Request $callback): Identity
        {
            return new Identity($request, $this->name, 'https://corp.test', (string) $callback->query('user'));
        }
    };

    $given = null;

    Keyring::sso()->extend('corp', function (array $config, string $name) use ($provider, &$given) {
        $given = [$config['realm'], $name];

        return $provider;
    });

    $url = ssoStart('corp');
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

    expect(ssoComplete(SSO_CALLBACK.'?user=ada&state='.$query['state'], 'corp')->subject)->toBe('ada')
        ->and($given)->toBe(['staff', 'corp']);

    // One that says a confirm asks it for a new sign in, which it can't be asked for.
    Keyring::sso()->extend('corp', fn (array $config, string $name) => new ($provider::class)($name, SsoFreshness::Reauthenticate));

    expect(fn () => Keyring::sso()->provider('corp'))
        ->toThrow(InvalidArgumentException::class, 'Identity provider [corp] can\'t be asked for a new sign in, so its "freshness" can\'t be reauthenticate.');
});

it('has the config\'s freshness win over what a driver of the app\'s own says', function () {
    $idp = new FakeIdentityProvider;
    // A driver that implements IdentityProvider itself, says reauthenticate
    // and never reads the config.
    Keyring::sso()->extend('corp', fn (array $config, string $name) => new readonly class($name, $idp) implements IdentityProvider
    {
        public function __construct(private string $name, private FakeIdentityProvider $idp) {}

        public function name(): string
        {
            return $this->name;
        }

        public function label(): string
        {
            return 'Corp';
        }

        public function supportsReauthentication(): bool
        {
            return true;
        }

        public function freshness(): SsoFreshness
        {
            return SsoFreshness::Reauthenticate;
        }

        public function authorizationUrl(AuthorizationRequest $request): string
        {
            return 'https://corp.test/login?state='.$request->state;
        }

        public function identify(AuthorizationRequest $request, Request $callback): Identity
        {
            return new Identity($request, $this->name, $this->idp->issuer, (string) $callback->query('user'));
        }
    });

    config(['keyring.sso.providers.corp' => ['driver' => 'corp']]);
    Keyring::factors([Password::class, SingleSignOn::class]);
    reloadRoutes();
    expect(Keyring::sso()->freshness('corp'))->toBe(SsoFreshness::Reauthenticate);

    config(['keyring.sso.providers.corp.freshness' => 'never']);
    $link = Authenticator::factory()->sso('corp', '42', $idp->issuer)->for(taylor(), 'authenticatable')->create();

    expect(Keyring::sso()->freshness('corp'))->toBe(SsoFreshness::Never)
        ->and(Keyring::factor('sso')->reauthenticates($link))->toBeFalse()
        ->and(Keyring::factor('sso')->wouldProve($link)->authenticatedAt)->toBe(Verification::UNKNOWN);

    config(['keyring.sso.providers.corp.freshness' => 'round_trip']);
    expect(Keyring::sso()->freshness('corp'))->toBe(SsoFreshness::RoundTrip)
        ->and(Keyring::factor('sso')->confirms($link))->toBeTrue()
        ->and(Keyring::factor('sso')->wouldProve($link)->authenticatedAt)->toBeNull();

    // A typo is refused, rather than left to the driver's default.
    config(['keyring.sso.providers.corp.freshness' => 'nevr']);
    expect(fn () => Keyring::sso()->provider('corp'))
        ->toThrow(InvalidArgumentException::class, 'Identity provider [corp] has a "freshness" that isn\'t reauthenticate, round_trip or never.')
        ->and(fn () => Keyring::sso()->freshness('corp'))->toThrow(InvalidArgumentException::class)
        ->and(Keyring::factor('sso')->confirms($link))->toBeFalse();
});

it('refuses a config that has a driver which can\'t be asked reauthenticate', function () {
    FakeIdentityProvider::github()->register('github');
    config(['keyring.sso.providers.github.freshness' => 'reauthenticate']);

    expect(fn () => Keyring::sso()->freshness('github'))->toThrow(InvalidArgumentException::class, 'can\'t be reauthenticate');
});

it('lets the app replace one of Keyring\'s drivers', function () {
    FakeIdentityProvider::google()->register('google');

    Keyring::sso()->extend('google', fn (array $config, string $name) => new class($name, $config) extends GoogleProvider
    {
        protected function defaultLabel(): string
        {
            return 'Google Workspace';
        }
    });

    expect(Keyring::sso()->provider('google')->label())->toBe('Google Workspace');
});

it('refuses a driver that builds a provider under another name', function () {
    config(['keyring.sso.providers.corp' => ['driver' => 'oidc-ish', 'client_id' => 'x']]);

    Keyring::sso()->extend('oidc-ish', fn (array $config) => new GitHubProvider('elsewhere', $config));

    Keyring::sso()->provider('corp');
})->throws(InvalidArgumentException::class, 'reports the name [elsewhere]');
