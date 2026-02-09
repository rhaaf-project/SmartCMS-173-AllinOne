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
        Schema::create('inbound_routes', function (Blueprint $table) {
            $table->id();
            $table->string('did_number');                        // DID/extension to match
            $table->string('description')->nullable();           // Route description
            $table->foreignId('trunk_id')->nullable()->constrained()->nullOnDelete();
            $table->string('destination_type')->default('extension'); // extension/ring_group/ivr/voicemail/hangup
            $table->unsignedBigInteger('destination_id')->nullable(); // FK to destination (e.g. extension_id)
            $table->string('cid_filter')->nullable();            // Caller ID filter
            $table->integer('priority')->default(0);             // Route priority
            $table->boolean('is_active')->default(true);
            $table->timestamps();

            $table->index(['did_number', 'priority']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('inbound_routes');
    }
};
