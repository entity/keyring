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
}
