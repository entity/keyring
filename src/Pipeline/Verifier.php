<?php

namespace Keyring\Pipeline;

use Illuminate\Contracts\Container\Container;
use Illuminate\Pipeline\Pipeline;
use Keyring\Contracts\Responses\AuthenticatedResponse;
use Keyring\Contracts\Responses\ChallengeResponse;
use Keyring\Contracts\Responses\FailedResponse;
use Keyring\Contracts\Responses\LockoutResponse;
use Keyring\Events\Attempting;
use Keyring\KeyringManager;
use Symfony\Component\HttpFoundation\Response;

/**
 * Sends a verification through the pipeline.
 */
class Verifier
{
    public function __construct(
        protected Container $container,
        protected KeyringManager $keyring,
    ) {}

    public function verify(Context $context): Context
    {
        Attempting::dispatch($context->request, $context->factor->key(), $context->purpose);

        return new Pipeline($this->container)
            ->send($context)
            ->through($this->keyring->steps())
            ->thenReturn();
    }

    /**
     * Verify, and answer with the response for how it went: signed in,
     * another factor needed, locked out or failed.
     */
    public function respond(Context $context): Response
    {
        $context = $this->verify($context);

        $contract = match ($context->outcome) {
            Outcome::Complete => AuthenticatedResponse::class,
            Outcome::Challenge => ChallengeResponse::class,
            Outcome::LockedOut => LockoutResponse::class,
            default => FailedResponse::class,
        };

        return $this->keyring->response($contract, context: $context)->toResponse($context->request);
    }
}
