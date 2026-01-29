<html>
<head>
    <title>Verify Email</title>
</head>
<body>
    <h2>Hello {{ $user->name }},</h2>
    <p>Please click the link below to verify your email address:</p>
    <a href="{{ $verificationUrl }}">Verify Email</a>
    <p>If you didn't create an account, no further action is required.</p>
</body>
</html>
