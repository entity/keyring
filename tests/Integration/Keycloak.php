<?php

declare(strict_types=1);

namespace Keyring\Tests\Integration;

use Dom\Element;
use Dom\HTMLDocument;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Psr7\Uri;
use GuzzleHttp\Psr7\UriResolver;
use Illuminate\Support\Str;
use PHPUnit\Framework\Assert;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * A Keycloak started by bin/keycloak, reached with Guzzle rather than
 * Laravel's HTTP client, so what Keyring sends it is all a test sees there.
 * Its browser() keeps cookies like a browser, so the user stays signed in at
 * Keycloak between sign ins, and follows no redirects: the one back to the
 * app's callback is where a test takes over.
 */
final class Keycloak
{
    public const string CLIENT_ID = 'keyring';

    public const string CLIENT_SECRET = 'keyring-secret';

    public const string USERNAME = 'taylor';

    public const string PASSWORD = 'password';

    public const string CALLBACK = 'http://localhost/auth/keycloak/callback';

    private readonly Client $browser;

    private ?string $adminToken = null;

    public function __construct(
        public readonly string $url,
        public readonly string $realm = 'keyring',
    ) {
        // Keycloak's cookies are Secure, which browsers keep for
        // http://127.0.0.1 and localhost as they would over HTTPS. Guzzle
        // drops them, so they're taken as plain cookies instead.
        $cookies = new class extends CookieJar
        {
            public function extractCookies(RequestInterface $request, ResponseInterface $response): void
            {
                $plain = array_map(fn (string $cookie) => (string) preg_replace('/;\s*Secure(?=;|$)/i', '', $cookie), $response->getHeader('Set-Cookie'));

                parent::extractCookies($request, $plain === [] ? $response : $response->withHeader('Set-Cookie', $plain));
            }
        };

        $this->browser = new Client(['cookies' => $cookies, 'allow_redirects' => false, 'http_errors' => false, 'timeout' => 10]);
    }

    public function issuer(): string
    {
        return "{$this->url}/realms/{$this->realm}";
    }

    /**
     * @return array<string, mixed>
     */
    public function discovery(): array
    {
        return $this->json(new Client(['timeout' => 10])->get($this->issuer().'/.well-known/openid-configuration'));
    }

    /**
     * Open the authorization URL, expect Keycloak's login form, and sign in
     * with it: the URL of the callback Keycloak sends the browser back to.
     * For a client that asks for consent, it's given or refused as $consent
     * says.
     */
    public function signIn(string $authorizationUrl, bool $consent = true, string $username = self::USERNAME): string
    {
        $form = $this->form($this->browser->get($authorizationUrl), '#kc-form-login');

        $response = $this->follow($this->browser->post($form->getAttribute('action') ?? '', [
            'form_params' => ['username' => $username, 'password' => self::PASSWORD, 'credentialId' => ''],
        ]));

        if ($response->getStatusCode() === 200) {
            $form = $this->form($response, 'form:has(input[name="code"])');

            // The consent form's action is a path.
            $response = $this->browser->post(UriResolver::resolve(new Uri($this->url), new Uri($form->getAttribute('action') ?? '')), [
                'form_params' => [
                    'code' => $form->querySelector('input[name="code"]')?->getAttribute('value'),
                    ($consent ? 'accept' : 'cancel') => 'Yes',
                ],
            ]);
        }

        return $this->callback($response);
    }

    /**
     * Open the authorization URL while signed in at Keycloak, and expect to
     * be sent straight back without being asked for a password.
     */
    public function passThrough(string $authorizationUrl): string
    {
        return $this->callback($this->browser->get($authorizationUrl));
    }

    /**
     * Follow redirects as far as they stay at Keycloak.
     */
    private function follow(ResponseInterface $response): ResponseInterface
    {
        while (str_starts_with($response->getHeaderLine('Location'), $this->url.'/')) {
            $response = $this->browser->get($response->getHeaderLine('Location'));
        }

        return $response;
    }

    /**
     * A new realm, with the client and user bin/keycloak sets up in the
     * one it makes. $client changes the client: "publicClient", say, or
     * among its "attributes", "id.token.signed.response.alg".
     *
     * @param  array<string, mixed>  $client
     */
    public function createRealm(string $realm, array $client = []): self
    {
        $this->admin('POST', '/admin/realms', [
            'id' => $realm,
            'realm' => $realm,
            'enabled' => true,
            'clients' => [array_replace_recursive([
                'clientId' => self::CLIENT_ID,
                'enabled' => true,
                'protocol' => 'openid-connect',
                'publicClient' => false,
                'secret' => self::CLIENT_SECRET,
                'standardFlowEnabled' => true,
                'directAccessGrantsEnabled' => false,
                'redirectUris' => [self::CALLBACK],
                'attributes' => ['pkce.code.challenge.method' => 'S256'],
            ], $client)],
            'users' => [[
                'username' => self::USERNAME,
                'email' => 'taylor@example.com',
                'emailVerified' => true,
                'firstName' => 'Taylor',
                'lastName' => 'Otwell',
                'enabled' => true,
                'credentials' => [['type' => 'password', 'value' => self::PASSWORD, 'temporary' => false]],
            ]],
        ]);

        return new self($this->url, $realm);
    }

    /**
     * Another user, whose password is PASSWORD too.
     */
    public function addUser(string $username): void
    {
        $this->admin('POST', "/admin/realms/{$this->realm}/users", [
            'username' => $username,
            'email' => "{$username}@example.com",
            'emailVerified' => true,
            'firstName' => Str::headline($username),
            'lastName' => 'Example',
            'enabled' => true,
            'credentials' => [['type' => 'password', 'value' => self::PASSWORD, 'temporary' => false]],
        ]);
    }

    public function deleteRealm(): void
    {
        $this->admin('DELETE', "/admin/realms/{$this->realm}");
    }

    /**
     * The user's ID at Keycloak, which its ID tokens name as the subject.
     */
    public function subject(): string
    {
        return $this->admin('GET', "/admin/realms/{$this->realm}/users?exact=true&username=".self::USERNAME)[0]['id'];
    }

    /**
     * The realm's signing key providers, as Keycloak's admin API lists them.
     *
     * @return list<array<string, mixed>>
     */
    public function keyProviders(): array
    {
        return $this->admin('GET', "/admin/realms/{$this->realm}/components?type=org.keycloak.keys.KeyProvider");
    }

    /**
     * Add a key provider that makes a new key: "rsa-generated" or
     * "ecdsa-generated", say. With the highest priority, Keycloak signs
     * with it from now on.
     *
     * @param  array<string, string>  $config
     */
    public function addKey(string $providerId, array $config = [], int $priority = 500): void
    {
        $this->admin('POST', "/admin/realms/{$this->realm}/components", [
            'name' => $providerId.'-'.Str::random(6),
            'providerId' => $providerId,
            'providerType' => 'org.keycloak.keys.KeyProvider',
            'parentId' => $this->realm,
            'config' => array_map(fn ($value) => [$value], ['priority' => (string) $priority, 'enabled' => 'true', 'active' => 'true', ...$config]),
        ]);
    }

    /**
     * Turn a key provider off, which takes its key out of the JWKS.
     *
     * @param  array<string, mixed>  $component
     */
    public function disableKey(array $component): void
    {
        $component['config']['enabled'] = ['false'];
        $component['config']['active'] = ['false'];

        $this->admin('PUT', "/admin/realms/{$this->realm}/components/{$component['id']}", $component);
    }

    /**
     * @param  array<string, mixed>|null  $body
     */
    private function admin(string $method, string $path, ?array $body = null): mixed
    {
        $this->adminToken ??= $this->json(new Client(['timeout' => 10])->post("{$this->url}/realms/master/protocol/openid-connect/token", [
            'form_params' => ['grant_type' => 'password', 'client_id' => 'admin-cli', 'username' => 'admin', 'password' => 'admin'],
        ]))['access_token'];

        $response = new Client(['timeout' => 30, 'http_errors' => false])->request($method, $this->url.$path, [
            'headers' => ['Authorization' => "Bearer {$this->adminToken}"],
            ...($body === null ? [] : ['json' => $body]),
        ]);

        Assert::assertLessThan(300, $response->getStatusCode(), "Keycloak's admin API refused {$method} {$path}: ".$this->describe($response));

        return json_decode((string) $response->getBody(), true);
    }

    private function form(ResponseInterface $response, string $selector): Element
    {
        $form = $response->getStatusCode() === 200
            ? HTMLDocument::createFromString((string) $response->getBody(), LIBXML_NOERROR)->querySelector($selector)
            : null;

        Assert::assertNotNull($form, "Keycloak showed no {$selector} form: ".$this->describe($response));

        return $form;
    }

    private function callback(ResponseInterface $response): string
    {
        $location = $response->getHeaderLine('Location');

        Assert::assertSame(302, $response->getStatusCode(), 'Keycloak didn\'t send the browser back: '.$this->describe($response));
        Assert::assertStringStartsWith(self::CALLBACK.'?', $location);

        return $location;
    }

    /**
     * @return array<string, mixed>
     */
    private function json(ResponseInterface $response): array
    {
        return json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
    }

    private function describe(ResponseInterface $response): string
    {
        $body = (string) $response->getBody();

        if (preg_match('/<title>(.*?)<\/title>.*?(?:id="input-error"|class="[^"]*alert[^"]*")[^>]*>(.*?)</s', $body, $matches) === 1) {
            $body = trim(strip_tags($matches[1].' '.$matches[2]));
        }

        return $response->getStatusCode().' '.$response->getHeaderLine('Location').' '.Str::limit(preg_replace('/\s+/', ' ', strip_tags($body)) ?? '', 400);
    }
}
