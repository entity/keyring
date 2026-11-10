<?php

namespace Keyring\Http\Controllers\Concerns;

use Keyring\Pipeline\Context;
use Keyring\Pipeline\Verifier;
use Symfony\Component\HttpFoundation\Response;

trait RespondsToVerification
{
    protected function verifyAndRespond(Context $context): Response
    {
        return app(Verifier::class)->respond($context);
    }
}
