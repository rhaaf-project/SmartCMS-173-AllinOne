<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('firewalls', function (Blueprint $table) {
            $table->id();
            $table->foreignId('call_server_id')->nullable()->constrained('call_servers')->nullOnDelete();
            $table->string('port'); // e.g., 8760, 5060
            $table->string('source')->default('any'); // e.g., any, 10.33.42.80
            $table->string('destination')->default('any'); // e.g., any
            $table->string('protocol'); // e.g., UDP, TCP, UDP/TCP
            $table->string('interface'); // e.g., eth1, eth2, eth1,eth2
            $table->string('direction'); // e.g., inbound, outbound, both
            $table->string('action'); // e.g., allow, block, drop
            $table->string('comment')->nullable();
            $table->boolean('is_enabled')->default(true);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('firewalls');
    }
};
