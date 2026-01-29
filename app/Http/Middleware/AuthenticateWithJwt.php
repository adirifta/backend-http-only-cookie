<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class AuthenticateWithJwt
{
    public function handle(Request $request, Closure $next)
    {
        try {
            // Log untuk debugging
            Log::info('AuthenticateWithJwt middleware called');

            // Ambil token dari cookie terlebih dahulu
            $token = $request->cookie('jwt_token');

            Log::info('Token from cookie: ' . ($token ? 'exists' : 'not found'));

            // Jika tidak ada di cookie, coba dari header Authorization
            if (!$token && $request->hasHeader('Authorization')) {
                $authHeader = $request->header('Authorization');
                Log::info('Authorization header: ' . $authHeader);
                $token = str_replace('Bearer ', '', $authHeader);
            }

            if (!$token) {
                Log::warning('No token found in request');
                return response()->json(['error' => 'Token not found'], 401);
            }

            Log::info('Token length: ' . strlen($token));
            Log::info('Token first 50 chars: ' . substr($token, 0, 50));

            // Autentikasi dengan token
            $user = JWTAuth::setToken($token)->authenticate();

            if (!$user) {
                Log::warning('User not found for token');
                return response()->json(['error' => 'User not found'], 401);
            }

            Log::info('User authenticated: ' . $user->email);

            // Attach user ke request dan auth
            auth()->setUser($user);
            $request->merge(['user' => $user]);

        } catch (TokenExpiredException $e) {
            Log::error('Token expired: ' . $e->getMessage());
            return response()->json(['error' => 'Token expired'], 401);
        } catch (TokenInvalidException $e) {
            Log::error('Token invalid: ' . $e->getMessage());
            return response()->json(['error' => 'Token invalid'], 401);
        } catch (JWTException $e) {
            Log::error('JWT Exception: ' . $e->getMessage());
            return response()->json(['error' => 'Token error: ' . $e->getMessage()], 401);
        } catch (\Exception $e) {
            Log::error('General exception: ' . $e->getMessage());
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
