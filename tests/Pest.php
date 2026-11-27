<?php

declare(strict_types=1);

use Keyring\Tests\Concurrency\ConcurrencyTestCase;
use Keyring\Tests\TestCase;

pest()->extend(TestCase::class)->in('Feature', 'Unit', 'Integration');
pest()->extend(ConcurrencyTestCase::class)->in('Concurrency');
