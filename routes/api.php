<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Middleware\AuthenticateWithJwt;
use App\Http\Middleware\RefreshTokenMiddleware;

Route::prefix('auth')->group(function () {
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/forgot-password', [AuthController::class, 'forgotPassword']);
    Route::post('/reset-password', [AuthController::class, 'resetPassword']);
    Route::get('/verify-email/{token}', [AuthController::class, 'verifyEmail']);

    // Refresh endpoint dengan middleware khusus
    Route::post('/refresh', [AuthController::class, 'refresh'])
        ->middleware([RefreshTokenMiddleware::class]);

    // Protected routes dengan middleware JWT
    Route::middleware([AuthenticateWithJwt::class])->group(function () {
        Route::post('/logout', [AuthController::class, 'logout']);
        Route::get('/me', [AuthController::class, 'me']);
        Route::post('/resend-verification', [AuthController::class, 'resendVerification']);
    });
});

// Test protected route
Route::middleware([AuthenticateWithJwt::class])->get('/protected', function () {
    return response()->json([
        'message' => 'This is a protected route',
        'user' => auth()->user()
    ]);
});
