<?php

declare(strict_types=1);

namespace Keyring\Contracts;

use Illuminate\Http\Request;

/**
 * A primary factor that can sign in without the user typing who they are,
 * like a discoverable passkey.
 */
interface DiscoverableFactor extends PrimaryFactor
{
    /**
     * Options the browser needs to start the sign in.
     *
     * @return array<string, mixed>
     */
    public function loginOptions(Request $request): array;
}
