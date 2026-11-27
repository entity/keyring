<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * When each account last lost or replaced a sign-in method it had for
 * "authenticator_changes.established_after", or its recovery codes: until
 * that long after, it can't do so again. And when its first password was
 * set from a session, which isn't established until that long after. One
 * row per user.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('keyring_sign_in_changes', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->morphs('authenticatable', 'keyring_sign_in_changes_owner_index');
            $table->timestamp('changed_at')->nullable()->index();
            $table->timestamp('password_set_at')->nullable()->index();
            $table->timestamps();

            $table->unique(['authenticatable_type', 'authenticatable_id'], 'keyring_sign_in_changes_owner_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('keyring_sign_in_changes');
    }
};
