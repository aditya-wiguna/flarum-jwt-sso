# Flarum JWT SSO Extension

A Flarum extension that provides Single Sign-On (SSO) authentication using JWT tokens from your main site.

## Features

- JWT-based authentication flow
- Automatic user creation and updates
- Secure token validation
- CSRF protection with state parameters
- Configurable user group assignment
- Optional override of default Flarum login
- Comprehensive error handling

## Installation

1. Install via Composer:
```bash
composer require aditya-wiguna/flarum-jwt-sso
```

2. Enable the extension:
```bash
php flarum extension:enable aditya-wiguna-flarum-jwt-sso
```

3. Run migrations:
```bash
php flarum migrate
```

4. Configure the extension in your Flarum admin panel.

## Configuration

### Admin Panel Settings

1. **Main Site URL**: Base URL of your authentication site
2. **Login URL**: URL where users are redirected for authentication
3. **Logout URL**: URL where users are redirected after logout (optional)
4. **JWT Secret Key**: Secret key used to verify JWT tokens
5. **JWT Issuer**: Expected issuer claim in tokens (optional)
6. **Default Groups**: Comma-separated group IDs for new users
7. **Override Login**: Replace Flarum's default login with SSO only

### Environment Variables (Recommended)

```bash
JWT_SSO_SECRET_KEY=your-secret-key-here
JWT_SSO_MAIN_SITE_URL=https://your-site.com
JWT_SSO_LOGIN_URL=https://your-site.com/auth/flarum
JWT_SSO_LOGOUT_URL=https://your-site.com/logout
JWT_SSO_ISSUER=your-domain.com
```

## Authentication Flow

1. User clicks login in Flarum
2. User is redirected to your main site with state parameter
3. User authenticates on your main site
4. Your main site redirects back to Flarum with JWT token
5. Flarum validates the JWT and creates/updates the user
6. User is logged into Flarum

## JWT Token Requirements

Your main site must return a JWT token with these claims:

### Required Claims
- `sub`: User ID in your system
- `email`: User's email address
- `exp`: Token expiration timestamp

### Optional Claims
- `iss`: Token issuer (validated if configured)
- `username`: Preferred username
- `name` or `display_name`: User's display name
- `avatar_url`: User's profile picture URL
- `iat`: Token issued at timestamp

### Example JWT Payload
```json
{
  "iss": "your-domain.com",
  "sub": "12345",
  "email": "user@example.com",
  "username": "johndoe",
  "name": "John Doe",
  "avatar_url": "https://example.com/avatar.jpg",
  "iat": 1640995200,
  "exp": 1640998800
}
```

## Main Site Integration

### Redirect URL Structure
Your login URL should accept these parameters:
- `return_url`: Where to redirect after authentication
- `state`: CSRF protection token

### Response URL Structure
After authentication, redirect to the return_url with:
- `token`: The JWT token
- `state`: The original state parameter
- `error`: Error message (if authentication failed)

### Example Implementation (PHP)
```php
// Handle Flarum authentication request
if (isset($_GET['return_url']) && isset($_GET['state'])) {
    $returnUrl = $_GET['return_url'];
    $state = $_GET['state'];
    
    // Authenticate user (your existing logic)
    if ($user->isAuthenticated()) {
        // Generate JWT token
        $payload = [
            'iss' => 'your-domain.com',
            'sub' => $user->id,
            'email' => $user->email,
            'username' => $user->username,
            'name' => $user->display_name,
            'avatar_url' => $user->avatar_url,
            'iat' => time(),
            'exp' => time() + 3600 // 1 hour
        ];
        
        $jwt = JWT::encode($payload, $secretKey, 'HS256');
        
        // Redirect back to Flarum
        $redirectUrl = $returnUrl . '?' . http_build_query([
            'token' => $jwt,
            'state' => $state
        ]);
        
        header('Location: ' . $redirectUrl);
        exit;
    } else {
        // Authentication failed
        $redirectUrl = $returnUrl . '?' . http_build_query([
            'error' => 'authentication_failed',
            'state' => $state
        ]);
        
        header('Location: ' . $redirectUrl);
        exit;
    }
}
```

## API Endpoints

The extension creates these routes:

- `GET /auth/sso/login` - Initiates SSO login flow
- `GET /auth/sso/callback` - Handles authentication callback
- `POST /auth/sso/logout` - Handles SSO logout

## Troubleshooting

### Common Issues

1. **"SSO configuration is incomplete"**
   - Ensure Main Site URL and Login URL are configured
   - Check that settings are saved properly

2. **"Invalid token signature"**
   - Verify the JWT secret key matches between systems
   - Ensure both systems use the same algorithm (HS256)

3. **"Token has expired"**
   - Check token expiration time on your main site
   - Ensure system clocks are synchronized

4. **"Invalid state parameter"**
   - Session storage issues
   - CSRF protection triggered
   - Clear browser cache and try again

### Debug Mode

Enable debug logging by adding this to your main site:

```php
// Log JWT payload before encoding
error_log('JWT Payload: ' . json_encode($payload));

// Log generated token
error_log('Generated JWT: ' . substr($jwt, 0, 50) . '...');
```

## Security Considerations

- Always use HTTPS in production
- Use strong, random JWT secret keys
- Implement short token expiration times
- Monitor authentication logs
- See SECURITY.md for detailed security guidelines

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This extension is licensed under the MIT License.

## Support

- Create an issue on GitHub for bug reports
- Check existing issues before creating new ones
- Provide detailed information about your setup