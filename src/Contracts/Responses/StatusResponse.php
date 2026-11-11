<?php

declare(strict_types=1);

namespace Keyring\Contracts\Responses;

use Illuminate\Contracts\Support\Responsable;

/**
 * Sent after every other action (a code sent, a device signed out, a
 * password changed...). Built with `status`, `data` and `redirect`.
 */
interface StatusResponse extends Responsable
{
    /**
     * The constructor arguments Keyring passes, by name.
     *
     * @var list<string>
     */
    public const array BUILT_WITH = ['status', 'data', 'redirect'];
}
