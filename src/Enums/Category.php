<?php

declare(strict_types=1);

namespace Keyring\Enums;

/**
 * The kind of evidence a factor provides. Two verifications only count as
 * multi-factor when they come from different categories.
 */
enum Category: string
{
    /** Something the user knows, like a password. */
    case Knowledge = 'knowledge';

    /** Something the user has, like a phone, security key or recovery codes. */
    case Possession = 'possession';

    /** Something the user is, like a fingerprint checked by their authenticator. */
    case Inherence = 'inherence';
}
