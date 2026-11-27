<?php

declare(strict_types=1);

namespace Keyring\Enums;

/**
 * Why an account's established sign-in methods can't be removed or
 * replaced just now.
 */
enum FreezeReason: string
{
    /** It has a sign-in method that isn't established yet. */
    case NewAuthenticator = 'new-authenticator';

    /** It removed or replaced an established one, or its recovery codes. */
    case RecentChange = 'recent-change';
}
