<?php

namespace Keyring\Pipeline;

use Illuminate\Contracts\Container\Container;
use Illuminate\Pipeline\Pipeline;
use Keyring\Events\Attempting;
use Keyring\KeyringManager;

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
}
