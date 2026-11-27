<?php

declare(strict_types=1);

namespace Keyring\Sso\Providers;

use InvalidArgumentException;
use Keyring\Enums\SsoFailure;
use Keyring\Exceptions\SsoFailed;
use Keyring\Sso\AuthorizationRequest;
use Keyring\Sso\Identity;
use Keyring\Sso\SignedToken;

/**
 * Sign in with Microsoft: OpenID Connect on the Microsoft identity platform
 * (Entra ID, and personal Microsoft accounts).
 *
 * "tenant" picks who can sign in: a tenant's ID or domain for that
 * organisation's accounts alone, "organizations" for any organisation's,
 * "consumers" for personal accounts, or "common" (the default) for both.
 * A single tenant has one issuer, and tokens have to come from it.
 *
 * The other three share one discovery document, whose issuer is a
 * template: https://login.microsoftonline.com/{tenantid}/v2.0. Each token
 * is from the tenant its user belongs to, named in its "tid" claim, so its
 * "iss" has to be that template with the token's own tid in it. Taking any
 * issuer on Microsoft's host instead would take a token whose "iss" and
 * "tid" disagree. The issuer kept is the tenant's own, so the same "sub" in
 * two tenants is two people. "organizations" refuses a token from the
 * personal accounts' tenant, which "common" takes. To let in only some
 * tenants, check the "tid" claim.
 *
 * Microsoft's "email" claim is not verified. In an organisation's tenant it
 * is whatever an administrator typed, and nothing stops a tenant from
 * giving its user someone else's address. So emailVerified is false for
 * every Microsoft identity, unless the token carries the xms_edov optional
 * claim (the address's domain is verified by the tenant that owns it) set
 * to true. Add xms_edov to the app registration's optional claims to get
 * it.
 *
 * Microsoft only puts auth_time in its ID tokens when the app registration
 * adds it as an optional claim (Token configuration, Add optional claim,
 * ID, auth_time), whatever the request asks. Its freshness is still
 * "reauthenticate" unless the config says otherwise, so a sign in is only
 * fresh as of when Microsoft says the user signed in, and without the
 * claim never is, and a confirm fails, reported with what to add. A new
 * sign in is asked for with prompt=login, which Microsoft documents, and
 * not with max_age=0, which it doesn't: Keyring checks auth_time itself.
 */
class MicrosoftProvider extends OidcProvider
{
    public const string AUTHORITY = 'https://login.microsoftonline.com';

    /**
     * The tenant every personal Microsoft account belongs to.
     */
    public const string CONSUMERS = '9188040d-6c67-4c5b-b112-36a304b66dad';

    protected const string TEMPLATE = self::AUTHORITY.'/{tenantid}/v2.0';

    protected const string GUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(string $name, array $config)
    {
        $tenant = $config['tenant'] ?? 'common';

        if (! is_string($tenant) || preg_match('/^[A-Za-z0-9.-]+$/D', $tenant) !== 1) {
            throw new InvalidArgumentException("Identity provider [{$name}] has an invalid tenant.");
        }

        // Microsoft writes tenant IDs in lowercase, and domains are the same either way.
        $tenant = strtolower($tenant);

        parent::__construct($name, [...$config, 'tenant' => $tenant, 'issuer' => self::AUTHORITY.'/'.$tenant.'/v2.0']);
    }

    protected function defaultLabel(): string
    {
        return 'Microsoft';
    }

    protected function reauthenticationParameters(int $maxAge): array
    {
        return $maxAge === 0 ? ['prompt' => 'login'] : ['max_age' => (string) $maxAge];
    }

    /**
     * A request for a recent sign in needs auth_time, which Microsoft only
     * sends once the app registration asks for it, so the failure says
     * how.
     */
    protected function identityFrom(AuthorizationRequest $request, array $tokens, array $query): Identity
    {
        $identity = parent::identityFrom($request, $tokens, $query);

        if ($request->maxAge !== null && ! isset($identity->claims['auth_time'])) {
            throw SsoFailed::because(SsoFailure::StaleAuthentication, "[{$this->name}] didn't say when the user signed in, which a request with max_age needs. Microsoft only sends auth_time as an optional claim: in the Microsoft Entra admin center, open the app registration, then Token configuration, Add optional claim, choose the ID token type and tick auth_time (or add {\"name\": \"auth_time\"} to optionalClaims.idToken in its manifest). See https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims. Or set the provider's \"freshness\" to \"never\".");
        }

        return $identity;
    }

    protected function trustsDiscoveredIssuer(string $issuer): bool
    {
        return match ($this->config['tenant']) {
            'common', 'organizations' => $issuer === self::TEMPLATE,
            'consumers' => $issuer === self::AUTHORITY.'/'.self::CONSUMERS.'/v2.0',
            // A tenant named by its domain is only known by its ID once
            // discovery answers.
            default => $this->isTenantIssuer($issuer) && ($issuer === $this->issuer() || preg_match('/^'.self::GUID.'$/D', $this->config['tenant']) !== 1),
        };
    }

    protected function acceptedIssuer(array $claims): ?string
    {
        if ($this->discoveredIssuer() !== self::TEMPLATE) {
            return parent::acceptedIssuer($claims);
        }

        $tenant = $claims['tid'] ?? null;

        // "organizations" shares the template with "common", but is for
        // work and school accounts alone: not the personal accounts' tenant.
        if (! is_string($tenant) || preg_match('/^'.self::GUID.'$/D', $tenant) !== 1
            || ($this->config['tenant'] === 'organizations' && $tenant === self::CONSUMERS)) {
            return null;
        }

        $issuer = str_replace('{tenantid}', $tenant, self::TEMPLATE);

        return ($claims['iss'] ?? null) === $issuer ? $issuer : null;
    }

    /**
     * With the template, every tenant's tokens are signed with keys from the
     * one key set, and a key Microsoft only signs one tenant's tokens with
     * says so in its "issuer". So, as Microsoft asks of multi-tenant apps,
     * a key with an "issuer" only vouches for a token whose "iss" it is,
     * with the token's own "tid" in place of {tenantid}.
     *
     * @param  list<array<array-key, mixed>>  $keys
     *
     * @throws SsoFailed
     */
    protected function signedByOneOf(SignedToken $token, array $keys): bool
    {
        if ($this->discoveredIssuer() !== self::TEMPLATE) {
            return parent::signedByOneOf($token, $keys);
        }

        $tenant = $token->claims['tid'] ?? null;
        $issuer = $token->claims['iss'] ?? null;

        return parent::signedByOneOf($token, array_values(array_filter($keys, fn (array $key) => ! array_key_exists('issuer', $key)
            || (is_string($key['issuer']) && is_string($tenant) && is_string($issuer) && str_replace('{tenantid}', $tenant, $key['issuer']) === $issuer))));
    }

    /**
     * With the template, which tenant the callback is from is only known
     * from the token, so here it only has to be one of Microsoft's. It's
     * held to the token's issuer once that's checked.
     */
    protected function acceptsIssuerParameter(string $issuer): bool
    {
        return $this->discoveredIssuer() === self::TEMPLATE ? $this->isTenantIssuer($issuer) : parent::acceptsIssuerParameter($issuer);
    }

    protected function emailVerified(array $claims): bool
    {
        return ($claims['xms_edov'] ?? null) === true;
    }

    protected function isTenantIssuer(string $issuer): bool
    {
        return preg_match('#^'.preg_quote(self::AUTHORITY, '#').'/'.self::GUID.'/v2\.0$#D', $issuer) === 1;
    }
}
