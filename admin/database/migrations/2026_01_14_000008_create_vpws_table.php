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
        Schema::create('vpws', function (Blueprint $table) {
            $table->id();
            $table->foreignId('call_server_id')->nullable()->constrained()->nullOnDelete();
            $table->string('name');
            $table->string('vpw_number')->nullable();
            $table->string('type')->default('point_to_point'); // point_to_point/multipoint/broadcast
            $table->string('source_extension')->nullable();
            $table->string('destination')->nullable();
            $table->integer('priority')->default(0);
            $table->text('description')->nullable();
            $table->boolean('is_active')->default(true);
            $table->timestamps();

            $table->index(['call_server_id', 'type']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('vpws');
    }
};
