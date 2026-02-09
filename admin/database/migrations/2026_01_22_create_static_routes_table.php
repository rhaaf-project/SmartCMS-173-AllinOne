<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('static_routes', function (Blueprint $table) {
            $table->id();
            $table->foreignId('call_server_id')->nullable()->constrained('call_servers')->nullOnDelete();
            $table->string('network'); // e.g., 13.44.13.0
            $table->string('subnet'); // e.g., 255.255.255.0
            $table->string('gateway'); // e.g., 13.44.13.2
            $table->string('device'); // e.g., Eth1
            $table->string('description')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('static_routes');
    }
};
