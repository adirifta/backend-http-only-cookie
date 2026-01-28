## Setup
### Install package yang diperlukan
```bash
composer require laravel/sanctum
composer require tymon/jwt-auth
```

### Publish Sanctum dan JWT
```bash
php artisan vendor:publish --provider="Laravel\Sanctum\SanctumServiceProvider"
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
```

### Generate JWT secret key
```bash
php artisan jwt:secret
```
