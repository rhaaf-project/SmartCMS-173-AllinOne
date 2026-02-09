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
        // Add head_office_id to call_servers so each HO can have multiple servers
        Schema::table('call_servers', function (Blueprint $table) {
            $table->foreignId('head_office_id')->nullable()->after('id')->constrained()->nullOnDelete();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('call_servers', function (Blueprint $table) {
            $table->dropForeign(['head_office_id']);
            $table->dropColumn('head_office_id');
        });
    }
};
