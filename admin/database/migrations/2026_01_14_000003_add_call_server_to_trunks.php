<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('trunks', function (Blueprint $table) {
            // Add call_server_id FK
            $table->foreignId('call_server_id')->nullable()->after('id')->constrained()->nullOnDelete();

            // Make channelid nullable for auto-generation
            $table->string('channelid')->nullable()->change();
        });

        // Drop unique constraint on channelid if exists
        Schema::table('trunks', function (Blueprint $table) {
            $table->dropUnique(['channelid']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('trunks', function (Blueprint $table) {
            $table->dropForeign(['call_server_id']);
            $table->dropColumn('call_server_id');
            $table->string('channelid')->unique()->change();
        });
    }
};
