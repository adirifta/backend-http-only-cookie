<?php

namespace App\Services;

use App\Interface\CookieServiceInterface;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie as CookieFacade;

class CookieService implements CookieServiceInterface
{
    private const COOKIE_NAME = 'jwt_token';
    private const COOKIE_LIFETIME = 60 * 24 * 7;

    public function createJwtCookie(string $token): \Symfony\Component\HttpFoundation\Cookie
    {
        return cookie(
            name: self::COOKIE_NAME,
            value: $token,
            minutes: self::COOKIE_LIFETIME,
            path: '/',
            domain: null,
            secure: config('app.env') === 'production',
            httpOnly: true,
            sameSite: 'Strict',
            raw: false
        );
    }

    public function forgetJwtCookie(): \Symfony\Component\HttpFoundation\Cookie
    {
        return CookieFacade::forget(self::COOKIE_NAME);
    }

    public function getTokenFromRequest(Request $request): ?string
    {
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
