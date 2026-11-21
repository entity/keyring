<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Where a test's listener keeps the ended sessions it heard about, on the
 * user's connection, as a job on a database queue would. Made here rather
 * than in the test: on MySQL a schema change commits the test's own
 * transaction, and the rollbacks the test checks for would have nothing to
 * roll back to.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('heard_endings', function (Blueprint $table) {
            $table->id();
            $table->string('handle');
            $table->string('reason');
        });
    }
};
