<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('keyring_password_holds', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->morphs('authenticatable', 'keyring_password_holds_owner_index');
            $table->string('reason')->nullable();
            $table->timestamps();

            $table->unique(['authenticatable_type', 'authenticatable_id'], 'keyring_password_holds_owner_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('keyring_password_holds');
    }
};
