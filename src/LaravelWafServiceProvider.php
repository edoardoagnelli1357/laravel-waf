<?php

namespace Edoardoagnelli1357\LaravelWaf;

use Edoardoagnelli1357\LaravelWaf\Support\Agent;
use Illuminate\Support\ServiceProvider;

class LaravelWafServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/Config/waf.php', 'waf');
        $this->app->singleton('agent', function ($app) {
            return new Agent($app['request']);
        });
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/Config/waf.php',
            __DIR__.'/Migrations/2025_12_09_123044_create_waf_logs_table.php',
            __DIR__.'/Migrations/2025_12_09_123100_create_waf_ips_table.php',
        ], 'waf');

    }
}
