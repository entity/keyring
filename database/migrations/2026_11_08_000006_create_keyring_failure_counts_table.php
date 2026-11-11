<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('keyring_failure_counts', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->morphs('authenticatable', 'keyring_failure_counts_owner_index');
            $table->string('factor', 64);
            // The authenticator's ID, or the factor's key for one with no
            // row of its own, like the password.
            $table->string('authenticator', 64);
            // Failures in a row from browsers the account hasn't signed in
            // from, and from those it has. Together they never pass the cap.
            $table->unsignedInteger('failures')->default(0);
            $table->unsignedInteger('known_failures')->default(0);
            // When each of the two was refused until the count is cleared.
            $table->timestamp('locked_at')->nullable();
            $table->timestamp('known_locked_at')->nullable();
            $table->timestamps();

            // One row per account and authenticator, so two first failures
            // at once can't each start a count.
            $table->unique(['authenticatable_type', 'authenticatable_id', 'authenticator'], 'keyring_failure_counts_authenticator_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('keyring_failure_counts');
    }
};
