<?php

namespace App\Interface;

interface TokenServiceInterface
{
    public function generateToken(array $credentials): string;
    public function invalidateToken(string $token): void;
    public function refreshToken(string $token): string;
    public function getPayload(string $token): array;
    public function validateToken(string $token): bool;
    public function authenticateWithToken(string $token): object;
}
