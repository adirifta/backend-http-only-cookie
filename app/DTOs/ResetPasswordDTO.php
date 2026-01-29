<?php

namespace App\DTOs;

use Illuminate\Http\Request;

class ResetPasswordDTO
{
    public function __construct(
        public readonly string $token,
        public readonly string $email,
        public readonly string $password,
        public readonly string $password_confirmation,
    ) {}

    public static function fromRequest(Request $request): self
    {
        return new self(
            token: $request->input('token'),
            email: $request->input('email'),
            password: $request->input('password'),
            password_confirmation: $request->input('password_confirmation'),
        );
    }
}
