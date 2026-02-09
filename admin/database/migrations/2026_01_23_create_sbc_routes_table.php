<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('sbc_routes', function (Blueprint $table) {
            $table->id();
            $table->foreignId('sbc_id')->constrained('sbcs')->onDelete('cascade');
            $table->string('pattern', 100);
            $table->string('prefix', 50)->nullable();
            $table->integer('strip')->default(0);
            $table->integer('priority')->default(1);
            $table->text('description')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sbc_routes');
    }
};
