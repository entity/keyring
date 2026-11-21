<?php

declare(strict_types=1);

namespace Keyring\Tests\Fixtures;

use Illuminate\Http\Request;
use Keyring\Enums\Assurance;
use Keyring\Login\StepUp;
use Symfony\Component\HttpFoundation\Response;

/**
 * An app's own step-up service, resolved by the container in Keyring's place.
 */
class AnsweringStepUp extends StepUp
{
    public function unlessFresh(Request $request, int $since, ?Assurance $level = null): Response
    {
        return response('asked by the subclass', 409);
    }
}
