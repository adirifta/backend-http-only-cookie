<?php

namespace App\Interface;

use App\DTOs\LoginDTO;
use App\DTOs\RegisterDTO;
use App\DTOs\ResetPasswordDTO;
use App\DTOs\UserResponseDTO;

interface AuthServiceInterface
{
    public function register(RegisterDTO $dto): array;
    public function login(LoginDTO $dto): array;
    public function logout(): void;
    public function refreshToken(string $token): string;
    public function verifyEmail(string $token): void;
    public function requestPasswordReset(string $email): string;
    public function resetPassword(ResetPasswordDTO $dto): void;
    public function getAuthenticatedUser(): UserResponseDTO;
}
