<?php

namespace Keyring\Tests\Feature;

use Keyring\Facades\Keyring;
use Keyring\Factors\Password;

/**
 * The conformance suite on a bare install: the password alone and no
 * features. Checks for features that are off skip, saying why.
 */
class BareConformanceTest extends ConformanceTest
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('keyring.features', []);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Keyring::factors([Password::class]);
    }
}
