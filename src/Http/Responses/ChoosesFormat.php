<?php

declare(strict_types=1);

namespace Keyring\Http\Responses;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

trait ChoosesFormat
{
    /**
     * Inertia requests get redirects like normal page visits. Plain XHR and
     * API clients get JSON.
     */
    protected function wantsJson(Request $request): bool
    {
        return $request->expectsJson() && ! $request->hasHeader('X-Inertia');
    }

    /**
     * Where to come back to once signed in or confirmed: a page visit comes
     * back to itself, anything else to the page it came from. The Referer
     * header is the caller's to set, so a page on another site is swapped
     * for home.
     */
    protected function intendedUrl(Request $request): string
    {
        if ($request->isMethod('GET') && ! $request->expectsJson()) {
            return $request->fullUrl();
        }

        $previous = url()->previous();
        $root = $request->getSchemeAndHttpHost();

        return $previous === $root || str_starts_with($previous, $root.'/')
            ? $previous
            : url()->to(config('keyring.home'));
    }

    /**
     * What Inertia answers with a full page visit to the URL, rather than
     * swapping the next page into the app already running.
     */
    protected function loadInFull(string $url): Response
    {
        return new Response(status: Response::HTTP_CONFLICT, headers: ['X-Inertia-Location' => $url]);
    }

    /**
     * Have the browser drop what it cached and stored for the site, as on
     * sign out. Not "cookies": that would also clear the device cookie and
     * make the next sign in look like a new device.
     *
     * @template T of Response
     *
     * @param  T  $response
     * @return T
     */
    protected function clearSiteData(Response $response): Response
    {
        $response->headers->set('Clear-Site-Data', '"cache", "storage"');

        return $response;
    }
}
