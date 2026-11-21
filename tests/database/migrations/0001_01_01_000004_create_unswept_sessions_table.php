<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * A sessions table as it is with the sweep's migration rolled back, for a
 * test of a process that still thinks the columns are there. Made here
 * rather than by rolling the migration back in the test: on MySQL a schema
 * change commits the test's own transaction, and a revocation that fails
 * would have no savepoint to roll back to.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('unswept_sessions', function (Blueprint $table) {
            $table->string('id', 64)->primary();
            $table->string('user_id');
            $table->string('user_type');
            $table->string('guard');
            $table->string('device_id', 26)->nullable()->index();
            $table->unsignedTinyInteger('assurance')->default(0);
            $table->string('ip', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->unsignedInteger('authenticated_at');
            $table->unsignedInteger('last_activity_at');
            $table->unsignedInteger('expires_at')->index();
            $table->unsignedInteger('revoked_at')->nullable();
            $table->string('replaced_by', 64)->nullable();
            $table->unsignedInteger('replaced_at')->nullable();
            $table->boolean('remembered')->default(false);
            $table->string('origin', 64)->nullable();

            $table->index(['user_type', 'user_id']);
        });
    }
};
