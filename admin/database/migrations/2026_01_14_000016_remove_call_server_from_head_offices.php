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
        // Remove call_server_id from head_offices (wrong direction)
        if (Schema::hasColumn('head_offices', 'call_server_id')) {
            Schema::table('head_offices', function (Blueprint $table) {
                $table->dropForeign(['call_server_id']);
                $table->dropColumn('call_server_id');
            });
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('head_offices', function (Blueprint $table) {
            $table->foreignId('call_server_id')->nullable()->after('customer_id')->constrained()->nullOnDelete();
        });
    }
};
