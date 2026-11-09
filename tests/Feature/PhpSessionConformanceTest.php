<?php

namespace Keyring\Tests\Feature;

/**
 * The conformance suite again, on PHP-serialized sessions, which apps made
 * before Laravel 13 still use.
 */
class PhpSessionConformanceTest extends ConformanceTest
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('session.serialization', 'php');
    }
}
