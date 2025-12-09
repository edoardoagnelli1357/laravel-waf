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
        Schema::create('waf_logs', function (Blueprint $table) {
            $table->id();
            $table->string('ip', 45)->index();
            $table->text('url');
            $table->string('method', 10);
            $table->text('user_agent')->nullable();
            $table->enum('threat', [
                'agent',
                'bot',
                'ip',
                'geo',
                'lfi',
                'php',
                'referrer',
                'rfi',
                'session',
                'sqli',
                'swear',
                'url',
                'whitelist',
                'xss',
            ])->default('custom');
            $table->enum('severity', ['low', 'medium', 'high', 'critical', 'unknown'])->default('low');
            $table->boolean('blocked')->default(false);
            $table->longText('payload')->nullable();

            $table->foreignId('ip_id')->nullable()->constrained('waf_ips')->cascadeOnDelete();
            $table->timestamps();
            $table->softDeletes();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('waf_logs');
    }
};
