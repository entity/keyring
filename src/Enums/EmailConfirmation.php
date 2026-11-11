<?php

declare(strict_types=1);

namespace Keyring\Enums;

/**
 * What confirming an email change from one of its links did.
 */
enum EmailConfirmation
{
    /** Both addresses that had to confirm have, and the change applied. */
    case Applied;

    /** This address confirmed; the other one still has to. */
    case NeedsOtherAddress;

    /** The link was wrong, used up, or the change can no longer apply. */
    case Invalid;
}
