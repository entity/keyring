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
 * JSON gets it too, with "frozen": why, until when, and which factors
 * could prove the change now ("skip"), by key.
 */
class SignInChangesFrozen extends ValidationException
{
    use ChoosesFormat;

    /**
     * The factors that could make the change now, by key: see FreezeSkips.
     * Empty when none can, or nobody asked.
     *
     * @var list<string>
     */
    public array $skip = [];

    public function __construct(public readonly Freeze $freeze, string $key = 'authenticator')
    {
        $validator = Validator::make([], []);
        $validator->errors()->add($key, $freeze->message());

        parent::__construct($validator);
    }

    /**
     * Say which factors could make the change now.
     *
     * @param  list<string>  $factors
     */
    public function skippableWith(array $factors): static
    {
        $this->skip = $factors;

        return $this;
    }

    public function render(Request $request): ?JsonResponse
    {
        if (! $this->wantsJson($request)) {
            return null;
        }

        return new JsonResponse([
            'message' => $this->getMessage(),
            'errors' => $this->errors(),
            'frozen' => [...$this->freeze->toArray(), 'skip' => $this->skip],
        ], $this->status);
    }
}
