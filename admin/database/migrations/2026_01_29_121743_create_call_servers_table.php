<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('call_servers', function (Blueprint $table) {
            $table->id();
            $table->foreignId('head_office_id')->nullable()->constrained('head_offices')->nullOnDelete();
            $table->string('name');
            $table->string('host');
            $table->integer('port')->default(5060);
            $table->boolean('is_active')->default(true);
            $table->text('description')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('call_servers');
    }
};
