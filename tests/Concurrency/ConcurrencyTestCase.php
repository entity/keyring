<?php

declare(strict_types=1);

namespace Keyring\Tests\Concurrency;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Keyring\Tests\TestCase;

/**
 * Races run their operations in other processes, which can't see into a
 * transaction. So the database is migrated as usual but nothing is wrapped
 * in one, and every table is emptied afterwards for the next test.
 */
abstract class ConcurrencyTestCase extends TestCase
{
    /** @var list<string|null> */
    protected array $connectionsToTransact = [];

    protected function tearDown(): void
    {
        foreach (Schema::getTableListing(schemaQualified: false) as $table) {
            if ($table !== 'migrations') {
                DB::table($table)->truncate();
            }
        }

        parent::tearDown();
    }
}
