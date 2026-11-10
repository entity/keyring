<?php

namespace Keyring\Http\Responses;

use Illuminate\Http\Request;

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
}
