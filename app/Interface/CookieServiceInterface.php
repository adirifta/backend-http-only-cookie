<?php

namespace App\Interface;

use Illuminate\Http\Request;

interface CookieServiceInterface
{
    public function createJwtCookie(string $token): \Symfony\Component\HttpFoundation\Cookie;
    public function forgetJwtCookie(): \Symfony\Component\HttpFoundation\Cookie;
    public function getTokenFromRequest(Request $request): ?string;
}
