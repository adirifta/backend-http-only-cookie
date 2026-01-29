<?php

namespace App\Providers;

use App\Interface\AuthServiceInterface;
use App\Interface\CookieServiceInterface;
use App\Interface\TokenServiceInterface;
use App\Services\AuthService;
use App\Services\CookieService;
use App\Services\JwtTokenService;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->app->singleton(AuthServiceInterface::class, AuthService::class);
        $this->app->singleton(TokenServiceInterface::class, JwtTokenService::class);
        $this->app->singleton(CookieServiceInterface::class, CookieService::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        //
    }
}
