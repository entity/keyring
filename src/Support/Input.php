<?php

namespace Keyring\Support;

use Illuminate\Http\Request;

final class Input
{
    /**
     * A request value as text, for the places that read one before anything
     * has validated it: the rate limits run first, and a page can be opened
     * with any query string. An array or a missing value is no text at all.
     */
    public static function text(Request $request, string $key): string
    {
        $value = $request->input($key);

        return is_string($value) ? $value : '';
    }
}
