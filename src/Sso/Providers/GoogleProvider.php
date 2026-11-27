<?php

declare(strict_types=1);

namespace Keyring\Sso\Providers;

use Keyring\Enums\SsoFreshness;

/**
 * Sign in with Google: OpenID Connect at accounts.google.com.
 *
 * Google's ID tokens name their issuer either way, with or without the
 * scheme, as its documentation warns, so both are taken and kept as the
 * one with it. Its email_verified is reliable for Gmail and Workspace
 * addresses. A Workspace account's domain is in the "hd" claim.
 *
 * Google only puts auth_time in its ID tokens for an app that's published,
 * verified and has "Session age claims" turned on in the Google Auth
 * Platform's settings, and then only when the claims parameter asks for
 * it. Nor does it document a way to have the user sign in again: it takes
 * no prompt=login, and doesn't document max_age. So its freshness is
 * never unless the config says otherwise: a sign in with Google is never
 * fresh, and the confirm page only offers it toward a level, never a
 * fresh verification. With "reauthenticate",
 * for an app that has session age claims, every request asks for
 * auth_time that way, and a request for a new sign in is sent as max_age
 * alone. A confirm through Google then only passes when its auth_time
 * shows the user did sign in again there.
 */
class GoogleProvider extends OidcProvider
{
    public const string ISSUER = 'https://accounts.google.com';

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(string $name, array $config)
    {
        parent::__construct($name, [...$config, 'issuer' => self::ISSUER]);
    }

    protected function defaultLabel(): string
    {
        return 'Google';
    }

    protected function defaultFreshness(): SsoFreshness
    {
        return SsoFreshness::Never;
    }

    /**
     * Google's discovery doesn't say so, but its documentation asks for
     * auth_time with the claims parameter.
     */
    protected function takesClaimsParameter(): bool
    {
        return true;
    }

    protected function reauthenticationParameters(int $maxAge): array
    {
        return ['max_age' => (string) $maxAge];
    }

    protected function acceptedIssuer(array $claims): ?string
    {
        return in_array($claims['iss'] ?? null, [self::ISSUER, 'accounts.google.com'], true) ? self::ISSUER : null;
    }
}
