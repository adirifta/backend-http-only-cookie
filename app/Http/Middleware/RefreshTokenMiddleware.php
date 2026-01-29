<?php

namespace App\Http\Middleware;

use App\Interface\CookieServiceInterface;
use App\Interface\TokenServiceInterface;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class RefreshTokenMiddleware
{
    public function __construct(
        private TokenServiceInterface $tokenService,
        private CookieServiceInterface $cookieService,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $token = $this->cookieService->getTokenFromRequest($request);

        if (!$token) {
            return response()->json([
                'message' => 'No token provided'
            ], 401);
        }

        try {
            $payload = $this->tokenService->getPayload($token);

            // Optional: Check if token is about to expire
            $exp = $payload['exp'] ?? 0;
            $timeToExpire = $exp - time();

            if ($timeToExpire < 300) { // 5 minutes before expiration
                Log::info('Token nearing expiration', [
                    'expires_in' => $timeToExpire,
                    'path' => $request->path(),
                ]);
            }

        } catch (\Exception $e) {
            Log::warning('Token validation failed in refresh middleware', [
                'error' => $e->getMessage(),
            ]);
        }

        return $next($request);
    }
}
