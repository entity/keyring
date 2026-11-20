<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * What keyring:sweep needs to announce every session that ends: when each
 * record's end was announced, why it ended, and how often a listener failed
 * for it. Only needed with the "database" session registry driver.
 *
 * Records revoked before now count as announced, so the first sweep doesn't
 * announce them all again. Pruning keeps only the last day's, so that's one
 * small update.
 */
return new class extends Migration
{
    public function getConnection(): ?string
    {
        return config('keyring.sessions.connection');
    }

    public function up(): void
    {
        $table = config('keyring.sessions.table', 'keyring_sessions');

        Schema::table($table, function (Blueprint $table) {
            $table->unsignedInteger('announced_at')->nullable();
            $table->string('end_reason', 32)->nullable();
            $table->unsignedTinyInteger('announce_attempts')->default(0);

            // What the sweep looks for: idle records, and revoked ones.
            $table->index('last_activity_at');
            $table->index('revoked_at');
        });

        DB::connection($this->getConnection())->table($table)->whereNotNull('revoked_at')->update(['announced_at' => DB::raw('revoked_at')]);
    }

    public function down(): void
    {
        Schema::table(config('keyring.sessions.table', 'keyring_sessions'), function (Blueprint $table) {
            $table->dropIndex(['last_activity_at']);
            $table->dropIndex(['revoked_at']);
            $table->dropColumn(['announced_at', 'end_reason', 'announce_attempts']);
        });
    }
};
