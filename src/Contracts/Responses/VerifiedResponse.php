<?php

declare(strict_types=1);

namespace Keyring\Contracts\Responses;

use Illuminate\Contracts\Support\Responsable;

/**
 * Sent once the user's email address is verified. Built with `justNow`:
 * whether that just happened, or it already was.
 */
interface VerifiedResponse extends Responsable
{
    /**
     * The constructor arguments Keyring passes, by name.
     *
     * @var list<string>
     */
    public const array BUILT_WITH = ['justNow'];
}
