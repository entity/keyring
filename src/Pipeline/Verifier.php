<?php

declare(strict_types=1);

namespace Keyring\Pipeline;

use Illuminate\Contracts\Container\Container;
use Illuminate\Pipeline\Pipeline;
use Keyring\Contracts\Responses\AuthenticatedResponse;
use Keyring\Contracts\Responses\ChallengeResponse;
use Keyring\Contracts\Responses\FailedResponse;
use Keyring\Contracts\Responses\LockoutResponse;
use Keyring\Events\Attempting;
use Keyring\KeyringManager;
use Keyring\Support\Refusal;
use Symfony\Component\HttpFoundation\Response;

/**
 * Sends a verification through the pipeline, inside a timebox so every
 * refusal takes the same time: a wrong proof, an unknown user, a right
 * proof a later step turns down, or one a rate limit refuses.
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

        // Around every step, not just the one that checks the proof: what
        // the rate limits read and write, and what listeners do with a
        // failure, differ with whether the account exists and is locked.
        return Refusal::timed(function () use ($context) {
            $context = new Pipeline($this->container)
                ->send($context)
                ->through($this->keyring->steps())
                ->thenReturn();

            return [$context, in_array($context->outcome, [Outcome::Challenge, Outcome::Complete], true)];
        });
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
