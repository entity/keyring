<?php

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Auth pages and responses are never cached, and never pass their URL on to
 * another site as a Referer: links from emails (resets, email changes, "this
 * wasn't me") carry their token in it.
 *
 * The app itself still gets the Referer. A single-page app keeps the policy
 * of the page it loaded on, so sending none at all from the login page would
 * strip it from every request after signing in, and "back" would lose its way.
 */
class PreventCaching
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        $response->headers->set('Cache-Control', 'no-store, private');
        $response->headers->set('Referrer-Policy', 'same-origin');

        return $response;
    }
}
