<?php

namespace Keyring\Http\Controllers\Concerns;

use Keyring\Contracts\Responses\AuthenticatedResponse;
use Keyring\Contracts\Responses\ChallengeResponse;
use Keyring\Contracts\Responses\FailedResponse;
use Keyring\Contracts\Responses\LockoutResponse;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Outcome;
use Keyring\Pipeline\Verifier;

trait RespondsToVerification
{
    protected function verifyAndRespond(Context $context): mixed
    {
        $context = app(Verifier::class)->verify($context);

        $contract = match ($context->outcome) {
            Outcome::Complete => AuthenticatedResponse::class,
            Outcome::Challenge => ChallengeResponse::class,
            Outcome::LockedOut => LockoutResponse::class,
            default => FailedResponse::class,
        };

        return app($contract, ['context' => $context])->toResponse($context->request);
    }
}
