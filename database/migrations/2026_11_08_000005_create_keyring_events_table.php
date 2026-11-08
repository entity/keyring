<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('keyring_events', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->nullableMorphs('authenticatable');
            $table->string('type', 64)->index();
            $table->string('factor', 64)->nullable();
            $table->string('device_id', 26)->nullable();
            $table->string('ip', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->json('meta')->nullable();
            $table->timestamp('seen_at')->nullable();
            $table->timestamp('created_at')->index();

            // Recent events of one type for a user, checked on every login.
            $table->index(['authenticatable_type', 'authenticatable_id', 'type', 'created_at'], 'keyring_events_owner_type_index');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('keyring_events');
    }
};
