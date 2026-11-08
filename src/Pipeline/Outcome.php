<?php

namespace Keyring\Pipeline;

enum Outcome
{
    /** The proof didn't match, or the user wasn't found. */
    case Failed;

    /** Too many attempts. */
    case LockedOut;

    /** Verified, but the requirement needs more. */
    case Challenge;

    /** The requirement is met. */
    case Complete;
}
