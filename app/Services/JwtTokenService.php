<?php

namespace App\Services;

use App\Interface\TokenServiceInterface;
use Illuminate\Support\Facades\Log;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class JwtTokenService implements TokenServiceInterface
{
    public function generateToken(array $credentials): string
    {
        if (!$token = JWTAuth::attempt($credentials)) {
            throw new \Exception('Could not create token', 401);
        }
        return $token;
    }

    public function invalidateToken(string $token): void
    {
        try {
            JWTAuth::invalidate(JWTAuth::setToken($token));
        } catch (JWTException $e) {
            Log::warning('Token invalidation failed: ' . $e->getMessage());
            throw new \Exception('Could not invalidate token', 500);
        }
    }

    public function refreshToken(string $token): string
    {
        try {
            return JWTAuth::setToken($token)->refresh();
        } catch (JWTException $e) {
            Log::error('Token refresh failed: ' . $e->getMessage());
            throw new \Exception('Could not refresh token', 401);
        }
    }

    public function getPayload(string $token): array
    {
        try {
            return JWTAuth::setToken($token)->getPayload()->toArray();
        } catch (JWTException $e) {
            throw new \Exception('Invalid token', 401);
        }
    }

    public function validateToken(string $token): bool
    {
        try {
            return (bool) JWTAuth::setToken($token)->check();
        } catch (JWTException $e) {
            return false;
        }
    }

    public function getToken(): ?string
    {
        try {
            return JWTAuth::getToken();
        } catch (JWTException $e) {
            return null;
        }
    }
}
