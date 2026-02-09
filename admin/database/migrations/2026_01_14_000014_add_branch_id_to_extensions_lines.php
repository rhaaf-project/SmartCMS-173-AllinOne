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
        // Add branch_id to extensions
        Schema::table('extensions', function (Blueprint $table) {
            $table->foreignId('branch_id')->nullable()->after('call_server_id')->constrained()->nullOnDelete();
        });

        // Add branch_id to lines
        Schema::table('lines', function (Blueprint $table) {
            $table->foreignId('branch_id')->nullable()->after('call_server_id')->constrained()->nullOnDelete();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('extensions', function (Blueprint $table) {
            $table->dropForeign(['branch_id']);
            $table->dropColumn('branch_id');
        });

        Schema::table('lines', function (Blueprint $table) {
            $table->dropForeign(['branch_id']);
            $table->dropColumn('branch_id');
        });
    }
};
