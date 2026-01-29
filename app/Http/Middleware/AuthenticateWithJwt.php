<?php

namespace App\Http\Middleware;

use App\Interface\CookieServiceInterface;
use App\Interface\TokenServiceInterface;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateWithJwt
{
    public function __construct(
        private TokenServiceInterface $tokenService,
        private CookieServiceInterface $cookieService,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        // Debug: Log semua cookies yang diterima
        Log::debug('AuthenticateWithJwt Middleware - Request Cookies:', [
            'all_cookies' => $request->cookies->all(),
            'has_jwt_token' => $request->hasCookie('jwt_token'),
            'jwt_token_value' => $request->cookie('jwt_token') ? 'EXISTS' : 'NULL',
            'path' => $request->path(),
            'method' => $request->method(),
            'origin' => $request->header('Origin'),
            'host' => $request->getHost(),
        ]);

        $token = $this->cookieService->getTokenFromRequest($request);

        if (!$token) {
            Log::warning('JWT Authentication: No token found in request', [
                'path' => $request->path(),
                'ip' => $request->ip(),
                'cookies_received' => array_keys($request->cookies->all()),
                'authorization_header' => $request->header('Authorization'),
            ]);

            return response()->json([
                'message' => 'Authentication required',
                'debug' => [
                    'cookies_received' => array_keys($request->cookies->all()),
                    'has_jwt_cookie' => $request->hasCookie('jwt_token'),
                ]
            ], 401);
        }

        Log::debug('Token found in request', [
            'token_length' => strlen($token),
            'token_preview' => substr($token, 0, 50) . '...',
        ]);

        try {
            // Authenticate dengan token
            $user = $this->tokenService->authenticateWithToken($token);

            // Set user ke auth dan request
            auth()->setUser($user);
            $request->merge(['user' => $user]);

            Log::debug('JWT Authentication successful', [
                'user_id' => $user->id,
                'email' => $user->email,
            ]);

        } catch (\Exception $e) {
            Log::warning('JWT Authentication failed', [
                'error' => $e->getMessage(),
                'token_preview' => substr($token, 0, 50),
                'token_length' => strlen($token),
            ]);

            return response()->json([
                'message' => 'Authentication failed',
                'error' => $e->getMessage(),
            ], 401);
        }

        return $next($request);
    }
}
