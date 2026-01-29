<!DOCTYPE html>
<html>
<head>
    <title>Reset Password</title>
</head>
<body>
    <h2>Hello {{ $user->name }},</h2>
    <p>You are receiving this email because we received a password reset request for your account.</p>
    <a href="{{ $resetUrl }}">Reset Password</a>
    <p>This password reset link will expire in 60 minutes.</p>
    <p>If you did not request a password reset, no further action is required.</p>
</body>
</html>
