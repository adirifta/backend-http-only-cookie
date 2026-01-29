<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Facades\Hash;

class UserService
{
    public function create(array $data): User
    {
        return User::create($data);
    }

    public function findByEmail(string $email): ?User
    {
        return User::where('email', $email)->first();
    }

    public function findByVerificationToken(string $token): ?User
    {
        return User::where('email_verification_token', $token)->first();
    }

    public function markEmailAsVerified(int $userId): bool
    {
        return User::where('id', $userId)->update([
            'email_verified_at' => now(),
            'email_verification_token' => null,
        ]);
    }

    public function updatePassword(int $userId, string $password): bool
    {
        return User::where('id', $userId)->update([
            'password' => Hash::make($password)
        ]);
    }
}
