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
        Schema::create('trunks', function (Blueprint $table) {
            $table->id();
            $table->string('name');                              // Trunk display name
            $table->string('channelid')->unique();               // Channel identifier
            $table->string('outcid')->nullable();                // Outbound Caller ID
            $table->integer('maxchans')->default(2);             // Max concurrent calls
            $table->boolean('disabled')->default(false);

            // PJSIP Settings
            $table->string('sip_server');                        // SIP server IP/hostname
            $table->integer('sip_server_port')->default(5060);   // SIP port
            $table->string('transport')->default('udp');         // udp/tcp/tls
            $table->string('context')->default('from-pstn');     // Dialplan context
            $table->string('codecs')->default('ulaw,alaw');      // Codec list
            $table->string('dtmfmode')->default('auto');         // DTMF mode
            $table->string('registration')->default('none');     // Registration type
            $table->string('auth_username')->nullable();         // SIP auth username
            $table->string('secret')->nullable();                // SIP password
            $table->boolean('qualify')->default(true);           // Enable qualify
            $table->integer('qualify_frequency')->default(60);   // Qualify interval

            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('trunks');
    }
};
