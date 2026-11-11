<?php

namespace Keyring\Support;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;

/**
 * What a request sent, read from where its method puts it: the body of a
 * POST (a form or JSON), and the query string of a GET, which has no body.
 * Laravel's own input() lays the query string under the body, so a POST's
 * password, code or token would work from its URL too, and a URL is kept in
 * logs, history and caches that a body never reaches.
 */
final class Input
{
    /**
     * Everything the request sent.
     *
     * @return array<array-key, mixed>
     */
    public static function all(Request $request): array
    {
        return match (true) {
            in_array($request->getRealMethod(), ['GET', 'HEAD'], true) => $request->query->all(),
            $request->isJson() => $request->json()->all(),
            default => $request->request->all(),
        };
    }

    /**
     * One value: a password, a code, a credential, a token posted to act on
     * something. Null when it wasn't sent.
     */
    public static function get(Request $request, string $key): mixed
    {
        return self::all($request)[$key] ?? null;
    }

    /**
     * A value as text, for the places that read one before anything has
     * validated it: the rate limits run first, and a page can be opened with
     * any query string. An array or a missing value is no text at all.
     */
    public static function text(Request $request, string $key): string
    {
        $value = self::get($request, $key);

        return is_string($value) ? $value : '';
    }

    /**
     * Validate what the request sent, so nothing a rule asks for can come
     * from the URL of a POST.
     *
     * @param  array<string, mixed>  $rules
     * @return array<string, mixed>
     *
     * @throws ValidationException
     */
    public static function validate(Request $request, array $rules): array
    {
        return Validator::make(self::all($request), $rules)->validate();
    }
}
