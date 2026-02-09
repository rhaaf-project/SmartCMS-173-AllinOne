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
        Schema::create('call_servers', function (Blueprint $table) {
            $table->id();
            $table->string('name');                              // Display name
            $table->string('host');                              // IP or hostname
            $table->integer('port')->default(5060);              // SIP port
            $table->text('description')->nullable();             // Optional description
            $table->boolean('is_active')->default(true);         // Active status
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('call_servers');
    }
};
