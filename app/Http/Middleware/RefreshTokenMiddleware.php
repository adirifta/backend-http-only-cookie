<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Log;

class RefreshTokenMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        Log::info('Refresh Token Middleware', [
            'path' => $request->path(),
            'has_jwt_cookie' => $request->hasCookie('jwt_token'),
            'cookies' => $request->cookies->all(),
        ]);

        // Ambil token dari cookie
        $token = $request->cookie('jwt_token');

        if (!$token) {
            Log::warning('No token found for refresh attempt');
            return response()->json(['error' => 'No token provided'], 401);
        }

        try {
            // Set token ke JWT
            JWTAuth::setToken($token);

            // Cek jika token valid (tidak expired)
            $payload = JWTAuth::getPayload();

            Log::info('Token payload before refresh', [
                'sub' => $payload->get('sub'),
                'exp' => date('Y-m-d H:i:s', $payload->get('exp')),
                'iat' => date('Y-m-d H:i:s', $payload->get('iat')),
            ]);

        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            // Token expired, tapi kita masih bisa refresh
            Log::info('Token expired but can be refreshed');
        } catch (\Exception $e) {
            Log::error('Invalid token for refresh', ['error' => $e->getMessage()]);
            return response()->json(['error' => 'Invalid token'], 401);
        }

        return $next($request);
    }
}
