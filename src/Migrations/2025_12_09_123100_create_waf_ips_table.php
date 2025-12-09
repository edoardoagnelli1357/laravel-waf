<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('waf_ips', function (Blueprint $table) {
            $table->id();
            $table->string('ip', length: 45)->index();
            $table->string('user_agent', 500)->default('unknown');
            $table->enum('type', ['allow', 'block', 'monitor'])->default('block');
            $table->string('reason')->nullable();
            $table->dateTime('expires_at')->nullable();
            $table->foreignId('log_id')->nullable()->unique()->constrained('waf_logs')->onDelete('');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('waf_ips');
    }
};
