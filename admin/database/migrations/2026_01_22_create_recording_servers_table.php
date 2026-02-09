<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('recording_servers', function (Blueprint $table) {
            $table->id();
            $table->foreignId('call_server_id')->nullable()->constrained('call_servers')->nullOnDelete();
            $table->string('ip_address');
            $table->string('port')->nullable();
            $table->string('pbx_system_type')->default('None'); // Dropdown selection
            $table->string('pbx_system_1')->nullable(); // PBX System 1 config
            $table->string('pbx_system_2')->nullable(); // PBX System 2 config
            $table->string('pbx_system_3')->nullable(); // PBX System 3 config
            $table->string('pbx_system_4')->nullable(); // PBX System 4 config
            $table->string('description')->nullable();
            $table->boolean('is_enabled')->default(true);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('recording_servers');
    }
};
