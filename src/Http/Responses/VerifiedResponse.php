<?php

declare(strict_types=1);

namespace Keyring\Http\Responses;

use Illuminate\Support\Uri;
use Keyring\Contracts\Responses\VerifiedResponse as VerifiedResponseContract;

class VerifiedResponse implements VerifiedResponseContract
{
    public function __construct(
        public readonly bool $justNow = false,
    ) {}

    /**
     * On to where they were going, with ?verified=1 when the link they
     * followed is what verified them.
     */
    public function toResponse($request)
    {
        $home = config('keyring.home');

        return redirect()->intended($this->justNow ? (string) Uri::of($home)->withQuery(['verified' => 1]) : $home);
    }
}
