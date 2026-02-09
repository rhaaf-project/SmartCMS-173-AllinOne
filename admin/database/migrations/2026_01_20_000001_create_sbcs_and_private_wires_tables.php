<?php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        // Create SBCs table
        Schema::create('sbcs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('call_server_id')->nullable()->constrained()->nullOnDelete();
            $table->string('name', 100);
            $table->string('sip_server', 255)->nullable();
            $table->integer('sip_server_port')->default(5060);
            $table->string('transport', 10)->default('udp');
            $table->string('context', 50)->default('from-pstn');
            $table->string('codecs', 100)->default('ulaw,alaw');
            $table->string('dtmfmode', 20)->default('auto');
            $table->string('registration', 20)->default('none');
            $table->string('auth_username', 100)->nullable();
            $table->string('secret', 100)->nullable();
            $table->string('outcid', 255)->nullable();
            $table->integer('maxchans')->default(2);
            $table->boolean('qualify')->default(true);
            $table->integer('qualify_frequency')->default(60);
            $table->boolean('disabled')->default(false);
            $table->timestamps();
        });

        // Create Private Wires table
        Schema::create('private_wires', function (Blueprint $table) {
            $table->id();
            $table->foreignId('call_server_id')->nullable()->constrained()->nullOnDelete();
            $table->string('name', 100);
            $table->string('number', 50)->nullable();
            $table->string('destination', 100)->nullable();
            $table->text('description')->nullable();
            $table->boolean('is_active')->default(true);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sbcs');
        Schema::dropIfExists('private_wires');
    }
};
