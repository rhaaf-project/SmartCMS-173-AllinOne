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
        if (!Schema::hasTable('extensions')) {
            Schema::create('extensions', function (Blueprint $table) {
                $table->id();
                // We use nullable foreign key for call_server_id as per previous migration logic (it might be added later)
                // But since we are creating it now, we can add it directly if call_servers table exists.
                // To be safe and compatible with 06 migration, we add it here or verify. 
                // The 06 migration tries to add it. To avoid conflict, we can omit it here OR handle it gracefully.
                // Better approach: Create the base table here.
                $table->string('extension', 20)->unique();
                $table->string('name')->nullable();
                $table->string('secret')->nullable(); // Voice password
                $table->string('context')->default('from-internal');
                $table->string('type')->default('sip'); // sip, pjsip, webrtc
                $table->foreignId('user_id')->nullable()->constrained()->nullOnDelete(); // Link to CMS user
                $table->boolean('is_active')->default(true);
                $table->timestamps();
            });
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('extensions');
    }
};
