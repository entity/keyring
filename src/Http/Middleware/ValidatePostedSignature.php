<?php

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Routing\Exceptions\InvalidSignatureException;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\URL;
use Keyring\Support\Input;
use Symfony\Component\HttpFoundation\Response;

/**
 * Checks a signed link's signature where its page posts it: in the body.
 *
 * An emailed link has to carry its signature in the URL. The page it opens
 * posts back to the same path, and with the signature still in that URL it
 * would be written to access logs and seen by proxies a second time, by the
 * request that acts. So the page posts "expires" and "signature" as fields,
 * and this checks them exactly as "signed:relative" checked the link: the
 * same signature, over the same path, with the same expiry.
 */
class ValidatePostedSignature
{
    public function handle(Request $request, Closure $next): Response
    {
        $link = Request::create('/'.$request->path().'?'.Arr::query([
            'expires' => Input::text($request, 'expires'),
            'signature' => Input::text($request, 'signature'),
        ]));

        throw_unless(URL::hasValidSignature($link, absolute: false), InvalidSignatureException::class);

        return $next($request);
    }
}
