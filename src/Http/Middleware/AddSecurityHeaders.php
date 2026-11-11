<?php

declare(strict_types=1);

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The headers every Keyring response is sent with. Auth pages and responses
 * are never cached, are only ever read as the type they say they are, and
 * never pass their URL on to another site as a Referer: links from emails
 * (resets, verification, email changes, "this wasn't me") carry their token
 * or signature in it.
 *
 * The app itself still gets the Referer. A single-page app keeps the policy
 * of the page it loaded on, so sending none at all from the login page would
 * strip it from every request after signing in, and "back" would lose its way.
 *
 * A page an emailed link opens has the link's token in its URL, so that one
 * sends no Referer to anyone: not to the app's own assets, and not to
 * whatever else the page loads.
 *
 * And none of them may be shown in a frame. Several of Keyring's pages act
 * on one press of a button (confirming an email change, undoing one,
 * reporting a device, verifying an address), which is what a page on
 * another site lines its own button up over. An app that has said how its
 * pages may be framed keeps its say.
 */
class AddSecurityHeaders
{
    /**
     * The pages emailed links open, and the route each one's form posts to.
     */
    protected const array EMAILED_LINKS = [
        'password.reset' => 'password.update',
        'verification.verify' => 'verification.verify.store',
        'keyring.email.confirm' => 'keyring.email.confirm.store',
        'keyring.email.revert' => 'keyring.email.revert.store',
        'keyring.devices.report' => 'keyring.devices.report.store',
    ];

    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        if ($this->leavesEmailedLink($request, $response)) {
            $response = $this->loadInFull((string) $response->headers->get('Location'));
        }

        $response->headers->set('Cache-Control', 'no-store, private');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('Referrer-Policy', $request->routeIs(...array_keys(self::EMAILED_LINKS)) ? 'no-referrer' : 'same-origin');

        if (! $this->saysWhoMayFrameIt($response)) {
            $response->headers->set('X-Frame-Options', 'DENY');
        }

        return $response;
    }

    /**
     * Whether the app has already decided how this response may be framed:
     * with an X-Frame-Options of its own, or a Content-Security-Policy that
     * has a frame-ancestors directive. A report-only policy decides nothing.
     */
    protected function saysWhoMayFrameIt(Response $response): bool
    {
        return $response->headers->has('X-Frame-Options') || array_any(
            $response->headers->all('Content-Security-Policy'),
            fn (?string $policy) => preg_match('/(?:^|[;,])\s*frame-ancestors(?=[\s;,]|$)/i', (string) $policy) === 1,
        );
    }

    /**
     * Whether an Inertia app is being sent on from an emailed link's page,
     * its form done. A form that failed goes back to the page it's on.
     */
    protected function leavesEmailedLink(Request $request, Response $response): bool
    {
        return $response->isRedirection()
            && $request->hasHeader('X-Inertia')
            && $request->routeIs(...array_values(self::EMAILED_LINKS))
            && $response->headers->get('Location') !== url()->previous();
    }

    /**
     * What Inertia answers with a full page visit. The app is still running
     * in the page the link opened, and swapping the next page in would leave
     * it sending no Referer from every page after, signed in or not. Anything
     * flashed for that page is in the session already.
     */
    protected function loadInFull(string $url): Response
    {
        return new Response(status: Response::HTTP_CONFLICT, headers: ['X-Inertia-Location' => $url]);
    }
}
