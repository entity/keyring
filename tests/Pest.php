<?php

use Keyring\Tests\Concurrency\ConcurrencyTestCase;
use Keyring\Tests\TestCase;

pest()->extend(TestCase::class)->in('Feature', 'Unit');
pest()->extend(ConcurrencyTestCase::class)->in('Concurrency');
