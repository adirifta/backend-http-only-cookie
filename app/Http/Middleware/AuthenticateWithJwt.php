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
        $token = $this->cookieService->getTokenFromRequest($request);

        if (!$token) {
            Log::warning('JWT Authentication: No token provided', [
                'path' => $request->path(),
                'ip' => $request->ip(),
            ]);

            return response()->json([
                'message' => 'Authentication required'
            ], 401);
        }

        try {
            if (!$this->tokenService->validateToken($token)) {
                throw new \Exception('Invalid token');
            }

            $payload = $this->tokenService->getPayload($token);

            // You can attach user info to request if needed
            $request->attributes->set('jwt_payload', $payload);

            Log::debug('JWT Authentication successful', [
                'user_id' => $payload['sub'] ?? null,
                'expires_at' => date('c', $payload['exp'] ?? 0),
            ]);

        } catch (\Exception $e) {
            Log::warning('JWT Authentication failed', [
                'error' => $e->getMessage(),
                'token_preview' => substr($token, 0, 50),
            ]);

            return response()->json([
                'message' => 'Authentication failed',
                'error' => $e->getMessage(),
            ], 401);
        }

        return $next($request);
    }
}
