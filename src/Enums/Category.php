<?php

namespace Keyring\Enums;

/**
 * The kind of evidence a factor provides. Two verifications only count as
 * multi-factor when they come from different categories, and only the first
 * three are authentication factors: they are what NIST SP 800-63B-4 counts
 * toward an assurance level.
 */
enum Category: string
{
    /** Something the user knows, like a password. */
    case Knowledge = 'knowledge';

    /** Something the user has, like a phone, security key or recovery codes. */
    case Possession = 'possession';

    /** Something the user is, like a fingerprint checked by their authenticator. */
    case Inherence = 'inherence';

    /**
     * Something sent to an address of theirs, like a code by email. It shows
     * whoever answers can read that address, which a password to the mailbox
     * is enough for, so NIST doesn't accept it as an authenticator (Sec.
     * 3.1.3.1). An app can ask for it as a step, but it never counts toward
     * a level.
     */
    case Address = 'address';

    /**
     * Whether this is an authentication factor, which counts toward an
     * assurance level, rather than a step an app chose to ask for.
     */
    public function authenticates(): bool
    {
        return $this !== self::Address;
    }
}
