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
        Schema::create('outbound_routes', function (Blueprint $table) {
            $table->id();
            $table->string('name');                              // Route name
            $table->foreignId('trunk_id')->constrained()->cascadeOnDelete();
            $table->string('dial_pattern')->default('.');        // Pattern to match (. = any)
            $table->string('match_cid')->nullable();             // Caller ID pattern filter (e.g. 7432X)
            $table->string('prepend_digits')->nullable();        // Digits to prepend
            $table->string('outcid')->nullable();                // Override Caller ID
            $table->integer('priority')->default(0);             // Route priority (lower = first)
            $table->boolean('is_active')->default(true);
            $table->text('description')->nullable();
            $table->timestamps();

            $table->index('priority');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('outbound_routes');
    }
};
