<?php

declare(strict_types=1);

namespace Keyring\Enums;

/**
 * Why a sign in through an identity provider didn't come back with someone.
 * Only Denied is the user's own doing: they said no on the provider's page.
 */
enum SsoFailure: string
{
    // The user declined, or closed the consent page (error=access_denied).
    case Denied = 'denied';

    // The callback's state is missing, unknown, already used, expired, or
    // was started for another provider.
    case InvalidState = 'invalid_state';

    // The provider answered the callback with an error of its own.
    case ProviderError = 'provider_error';

    // The callback isn't one the provider would send: no code, or an "iss"
    // that isn't the provider's (RFC 9207).
    case InvalidResponse = 'invalid_response';

    // The code couldn't be exchanged for tokens.
    case ExchangeFailed = 'exchange_failed';

    // The ID token failed a check: its signature, issuer, audience, times
    // or nonce.
    case InvalidToken = 'invalid_token';

    // The provider's metadata, keys or user API couldn't be read.
    case Unavailable = 'unavailable';

    // Asked to have the user sign in again (max_age), the provider didn't
    // say they had: its ID token has no auth_time, or one that's too old.
    case StaleAuthentication = 'stale_authentication';
}
