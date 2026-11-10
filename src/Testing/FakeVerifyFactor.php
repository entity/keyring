<?php

namespace Keyring\Testing;

use Keyring\Login\Verification;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Steps\VerifyFactor;

/**
 * The VerifyFactor step as Keyring::fake() swaps it in: a factor the test
 * decided passes or fails without its proof, and every check is noted for
 * the fake's assertions. Identifying the user still runs for real.
 *
 * In production it's the real step, whoever bound it.
 */
class FakeVerifyFactor extends VerifyFactor
{
    /**
     * A decided factor needs nothing in the request.
     */
    protected function rules(Context $context): array
    {
        return $this->decision($context) === null ? parent::rules($context) : [];
    }

    protected function check(Context $context): ?Verification
    {
        $verification = match ($this->decision($context)) {
            null => parent::check($context),
            true => Verification::of($context->authenticator()),
            false => null,
        };

        $this->fake()?->record($context->factor->key(), $verification !== null);

        return $verification;
    }

    /**
     * True to pass, false to fail, null to check for real.
     */
    protected function decision(Context $context): ?bool
    {
        return $this->fake()?->decision($context->factor->key());
    }

    protected function fake(): ?KeyringFake
    {
        return app()->isProduction() ? null : $this->container->make(KeyringFake::class);
    }
}
