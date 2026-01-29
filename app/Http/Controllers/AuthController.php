<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use App\Mail\VerifyEmail;
use App\Mail\ResetPassword;
use Illuminate\Auth\Events\PasswordReset;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Password;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ]);

        $verificationToken = Str::random(60);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'email_verification_token' => $verificationToken,
        ]);

        Mail::to($user->email)->send(new VerifyEmail($user, $verificationToken));

        return response()->json([
            'message' => 'User registered successfully. Please check your email for verification.'
        ], 201);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        $credentials = $request->only('email', 'password');

        // Gunakan JWTAuth langsung untuk autentikasi
        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(['error' => 'Invalid credentials'], 401);
        }

        $user = User::select('id', 'name', 'email', 'email_verified_at')->where('email', $request->email)->first();

        if (!$user->email_verified_at) {
            return response()->json(['error' => 'Email not verified'], 403);
        }

        // Buat cookie HttpOnly
        $cookie = cookie(
            'jwt_token',
            $token,
            60 * 24 * 7,
            '/',
            null,
            config('app.env') === 'production',
            true,
            false,
            'Strict'
        );

        return response()->json([
            'user' => $user,
            'message' => 'Login successful'
        ])->withCookie($cookie);
    }

    public function logout()
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
        } catch (\Exception $e) {
            // Log error jika ada
            Log::error('Logout error: ' . $e->getMessage());
        }

        $cookie = Cookie::forget('jwt_token');

        return response()->json([
            'message' => 'Logout successful'
        ])->withCookie($cookie);
    }

    public function me()
    {
        try {
            // Coba beberapa cara untuk mendapatkan user
            if (auth()->check()) {
                $user = auth()->user();
            } elseif (JWTAuth::getToken()) {
                $user = JWTAuth::authenticate();
            } else {
                return response()->json(['error' => 'Not authenticated'], 401);
            }

            if (!$user) {
                return response()->json(['error' => 'User not found'], 404);
            }

            return response()->json([
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'email_verified_at' => $user->email_verified_at,
                ]
            ]);

        } catch (\Exception $e) {
            Log::error('Me endpoint error: ' . $e->getMessage());
            return response()->json(['error' => 'Authentication failed'], 401);
        }
    }

    public function verifyEmail($token)
    {
        $user = User::where('email_verification_token', $token)->first();

        if (!$user) {
            return response()->json(['error' => 'Invalid verification token'], 400);
        }

        $user->email_verified_at = now();
        $user->email_verification_token = null;
        $user->save();

        return response()->json(['message' => 'Email verified successfully']);
    }

    public function forgotPassword(Request $request)
    {
        $request->validate(['email' => 'required|email']);

        $status = Password::sendResetLink(
            $request->only('email')
        );

        return $status === Password::RESET_LINK_SENT
            ? response()->json(['message' => __($status)], 200)
            : response()->json(['message' => __($status)], 400);
    }

    public function resetPassword(Request $request)
    {
        $request->validate([
            'token' => 'required',
            'email' => 'required|email',
            'password' => 'required|string|min:8|confirmed',
        ]);

        $status = Password::broker()->reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function (User $user, string $password) {
                $user->forceFill([
                    'password' => Hash::make($password)
                ]);

                $user->save();

                event(new PasswordReset($user));
            }
        );

        return $status === Password::PASSWORD_RESET
            ? response()->json(['message' => __($status)], 200)
            : response()->json(['error' => __($status)], 400);
    }

    public function refresh()
    {
        try {
            $newToken = JWTAuth::refresh();

            $cookie = cookie(
                'jwt_token',
                $newToken,
                60 * 24 * 7,
                '/',
                null,
                config('app.env') === 'production',
                true,
                false,
                'Strict'
            );

            return response()->json(['message' => 'Token refreshed'])->withCookie($cookie);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Token refresh failed: ' . $e->getMessage()], 401);
        }
    }
}
