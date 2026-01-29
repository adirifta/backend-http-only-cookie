<?php

namespace App\Services;

use App\DTOs\RegisterDTO;
use App\DTOs\LoginDTO;
use App\DTOs\ResetPasswordDTO;
use App\DTOs\UserResponseDTO;
use App\Interface\AuthServiceInterface;
use App\Interface\TokenServiceInterface;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Password;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;
use App\Mail\VerifyEmail;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthService implements AuthServiceInterface
{
    public function __construct(
        private TokenServiceInterface $tokenService,
        private UserService $userService,
    ) {}

    public function register(RegisterDTO $dto): array
    {
        $verificationToken = Str::random(60);

        $user = $this->userService->create([
            'name' => $dto->name,
            'email' => $dto->email,
            'password' => Hash::make($dto->password),
            'email_verification_token' => $verificationToken,
        ]);

        $this->sendVerificationEmail($user, $verificationToken);

        return [
            'message' => 'User registered successfully. Please check your email for verification.',
            'user_id' => $user->id,
        ];
    }

    public function login(LoginDTO $dto): array
    {
        $user = $this->userService->findByEmail($dto->email);

        if (!$user || !Hash::check($dto->password, $user->password)) {
            throw new \Exception('Invalid credentials', 401);
        }

        if (!$user->email_verified_at) {
            throw new \Exception('Email not verified', 403);
        }

        $token = $this->tokenService->generateToken([
            'email' => $dto->email,
            'password' => $dto->password,
        ]);

        return [
            'token' => $token,
            'user' => UserResponseDTO::fromModel($user),
        ];
    }

    public function logout(): void
    {
        try {
            $this->tokenService->invalidateToken(
                $this->tokenService->getToken()
            );
        } catch (JWTException $e) {
            Log::warning('Token invalidation failed during logout: ' . $e->getMessage());
        }
    }

    public function refreshToken(string $token): string
    {
        return $this->tokenService->refreshToken($token);
    }

    public function verifyEmail(string $token): void
    {
        $user = $this->userService->findByVerificationToken($token);

        if (!$user) {
            throw new \Exception('Invalid verification token', 400);
        }

        $this->userService->markEmailAsVerified($user->id);
    }

    public function requestPasswordReset(string $email): string
    {
        $status = Password::sendResetLink(['email' => $email]);

        if ($status !== Password::RESET_LINK_SENT) {
            throw new \Exception(__($status), 400);
        }

        return $status;
    }

    public function resetPassword(ResetPasswordDTO $dto): void
    {
        $status = Password::broker()->reset(
            [
                'email' => $dto->email,
                'password' => $dto->password,
                'password_confirmation' => $dto->password_confirmation,
                'token' => $dto->token,
            ],
            function (User $user, string $password) {
                $user->forceFill([
                    'password' => Hash::make($password)
                ])->save();

                event(new PasswordReset($user));
            }
        );

        if ($status !== Password::PASSWORD_RESET) {
            throw new \Exception(__($status), 400);
        }
    }

    public function getAuthenticatedUser(): UserResponseDTO
    {
        $user = auth()->user();

        if (!$user) {
            throw new \Exception('Not authenticated', 401);
        }

        return UserResponseDTO::fromModel($user);
    }

    private function sendVerificationEmail(User $user, string $token): void
    {
        try {
            Mail::to($user->email)->send(new VerifyEmail($user, $token));
        } catch (\Exception $e) {
            Log::error('Failed to send verification email: ' . $e->getMessage());
            throw new \Exception('Failed to send verification email', 500);
        }
    }
}
