<?php

declare(strict_types=1);

namespace Keyring\Exceptions;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use Keyring\Changes\Freeze;
use Keyring\Http\Responses\ChoosesFormat;

/**
 * An established sign-in method, or a set of recovery codes, was kept
 * because the account's sign-in methods changed too recently. A page
 * request gets the message as a validation error on $key, like any other;
 * JSON gets it too, with "frozen": why, and until when.
 */
class SignInChangesFrozen extends ValidationException
{
    use ChoosesFormat;

    public function __construct(public readonly Freeze $freeze, string $key = 'authenticator')
    {
        $validator = Validator::make([], []);
        $validator->errors()->add($key, $freeze->message());

        parent::__construct($validator);
    }

    public function render(Request $request): ?JsonResponse
    {
        if (! $this->wantsJson($request)) {
            return null;
        }

        return new JsonResponse([
            'message' => $this->getMessage(),
            'errors' => $this->errors(),
            'frozen' => $this->freeze->toArray(),
        ], $this->status);
    }
}
