<?php

namespace App\Services;

use App\Interface\CookieServiceInterface;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie as CookieFacade;
use Illuminate\Support\Facades\Log;

class CookieService implements CookieServiceInterface
{
    private const COOKIE_NAME = 'jwt_token';
    private const COOKIE_LIFETIME = 60 * 24 * 7; // 7 days in minutes

    public function createJwtCookie(string $token): \Symfony\Component\HttpFoundation\Cookie
    {
        $isProduction = config('app.env') === 'production';
        $domain = $isProduction ? config('app.domain', 'backend-laravel-http-only-cookie.test') : null;

        return cookie(
            name: self::COOKIE_NAME,
            value: $token,
            minutes: self::COOKIE_LIFETIME,
            path: '/',
            domain: $domain,
            secure: $isProduction,
            httpOnly: true,
            sameSite: $isProduction ? 'None' : 'Lax', // 'None' untuk cross-origin di production
            raw: false
        );
    }

    public function forgetJwtCookie(): \Symfony\Component\HttpFoundation\Cookie
    {
        $isProduction = config('app.env') === 'production';
        $domain = $isProduction ? config('app.domain') : null;

        $cookie = CookieFacade::forget(
            name: self::COOKIE_NAME,
            path: '/',
            domain: $domain
        );

        // Untuk sameSite: 'None' di production
        if ($isProduction) {
            $cookie->withSameSite('None');
        }

        return $cookie;
    }

    public function getTokenFromRequest(Request $request): ?string
    {
        // Log untuk debugging
        if (config('app.debug')) {
            Log::debug('CookieService - Request cookies:', [
                'all_cookies' => $request->cookie(),
                'has_jwt_cookie' => $request->hasCookie(self::COOKIE_NAME),
                'jwt_cookie_value' => $request->cookie(self::COOKIE_NAME),
            ]);
        }

        // Priority: Cookie > Authorization Header
        if ($token = $request->cookie(self::COOKIE_NAME)) {
            return $token;
        }

        if ($request->hasHeader('Authorization')) {
            $authHeader = $request->header('Authorization');
            if (str_starts_with($authHeader, 'Bearer ')) {
                return substr($authHeader, 7);
            }
        }

        return null;
    }
}
