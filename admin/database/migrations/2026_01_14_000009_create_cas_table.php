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
        Schema::create('cas', function (Blueprint $table) {
            $table->id();
            $table->foreignId('call_server_id')->nullable()->constrained()->nullOnDelete();
            $table->string('name');
            $table->integer('channel_number')->nullable();
            $table->string('signaling_type')->default('e_and_m'); // e_and_m/loop_start/ground_start/wink
            $table->foreignId('trunk_id')->nullable()->constrained()->nullOnDelete();
            $table->integer('span')->nullable();           // E1/T1 span number
            $table->integer('timeslot')->nullable();       // Timeslot within span
            $table->text('description')->nullable();
            $table->boolean('is_active')->default(true);
            $table->timestamps();

            $table->index(['call_server_id', 'signaling_type']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('cas');
    }
};
