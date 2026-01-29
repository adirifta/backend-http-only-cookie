<?php

namespace App\Http\Controllers;

use App\DTOs\LoginDTO;
use App\DTOs\RegisterDTO;
use App\DTOs\ResetPasswordDTO;
use App\Interface\AuthServiceInterface;
use App\Interface\CookieServiceInterface;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function __construct(
        private AuthServiceInterface $authService,
        private CookieServiceInterface $cookieService,
    ) {}

    public function register(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $dto = RegisterDTO::fromRequest($request);
            $result = $this->authService->register($dto);

            return response()->json($result, 201);
        } catch (\Exception $e) {
            Log::error('Registration failed: ' . $e->getMessage());

            return response()->json([
                'message' => $e->getMessage()
            ], $e->getCode() ?: 500);
        }
    }

    public function login(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $dto = LoginDTO::fromRequest($request);
            $result = $this->authService->login($dto);

            $cookie = $this->cookieService->createJwtCookie($result['token']);

            $response = response()->json([
                'user' => $result['user']->toArray(),
                'message' => 'Login successful'
            ]);

            // Attach cookie to response
            $response->withCookie($cookie);

            // Add headers for CORS
            $response->headers->set('Access-Control-Allow-Credentials', 'true');
            $response->headers->set('Access-Control-Expose-Headers', 'Set-Cookie');

            return $response;

        } catch (\Exception $e) {
            Log::warning('Login attempt failed: ' . $e->getMessage());

            return response()->json([
                'message' => $e->getMessage()
            ], $e->getCode() ?: 401);
        }
    }

    public function logout(): JsonResponse
    {
        try {
            $this->authService->logout();

            $cookie = $this->cookieService->forgetJwtCookie();

            $response = response()->json([
                'message' => 'Logout successful'
            ]);

            $response->withCookie($cookie);

            return $response;

        } catch (\Exception $e) {
            Log::error('Logout failed: ' . $e->getMessage());

            return response()->json([
                'message' => 'Logout failed'
            ], 500);
        }
    }

    public function me(Request $request): JsonResponse
    {
        $this->logRequestInfo($request);

        try {
            $user = $this->authService->getAuthenticatedUser();

            return response()->json([
                'user' => $user->toArray()
            ]);
        } catch (\Exception $e) {
            Log::error('Me endpoint error: ' . $e->getMessage());

            return response()->json([
                'message' => $e->getMessage()
            ], $e->getCode() ?: 401);
        }
    }

    public function verifyEmail(string $token): JsonResponse
    {
        try {
            $this->authService->verifyEmail($token);

            return response()->json([
                'message' => 'Email verified successfully'
            ]);
        } catch (\Exception $e) {
            Log::error('Email verification failed: ' . $e->getMessage());

            return response()->json([
                'message' => $e->getMessage()
            ], $e->getCode() ?: 400);
        }
    }

    public function forgotPassword(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $status = $this->authService->requestPasswordReset($request->email);

            return response()->json([
                'message' => __($status)
            ]);
        } catch (\Exception $e) {
            Log::error('Password reset request failed: ' . $e->getMessage());

            return response()->json([
                'message' => $e->getMessage()
            ], $e->getCode() ?: 400);
        }
    }

    public function resetPassword(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'token' => 'required',
            'email' => 'required|email',
            'password' => 'required|string|min:8|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $dto = ResetPasswordDTO::fromRequest($request);
            $this->authService->resetPassword($dto);

            return response()->json([
                'message' => 'Password reset successfully'
            ]);
        } catch (\Exception $e) {
            Log::error('Password reset failed: ' . $e->getMessage());

            return response()->json([
                'message' => $e->getMessage()
            ], $e->getCode() ?: 400);
        }
    }

    public function refresh(Request $request): JsonResponse
    {
        try {
            $token = $this->cookieService->getTokenFromRequest($request);

            if (!$token) {
                return response()->json([
                    'message' => 'No token provided'
                ], 401);
            }

            $newToken = $this->authService->refreshToken($token);
            $cookie = $this->cookieService->createJwtCookie($newToken);

            $response = response()->json([
                'message' => 'Token refreshed successfully'
            ]);

            $response->withCookie($cookie);

            return $response;

        } catch (\Exception $e) {
            Log::error('Token refresh failed: ' . $e->getMessage());

            return response()->json([
                'message' => $e->getMessage()
            ], $e->getCode() ?: 401);
        }
    }

    private function logRequestInfo(Request $request): void
    {
        if (config('app.debug')) {
            Log::debug('Auth API Request Info', [
                'origin' => $request->header('Origin'),
                'path' => $request->path(),
                'has_jwt_cookie' => $request->hasCookie('jwt_token'),
                'method' => $request->method(),
            ]);
        }
    }
}
