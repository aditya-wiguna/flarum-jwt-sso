<?php

namespace AdityaWiguna\JwtSSO\Controller;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Flarum\Foundation\ValidationException;
use Flarum\Http\RequestUtil;
use Flarum\Settings\SettingsRepositoryInterface;
use Flarum\User\User;
use Flarum\User\UserRepository;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\Response\RedirectResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class SSOController implements RequestHandlerInterface
{
    protected $settings;
    protected $users;
    protected $events;
    protected $cache;

    // Rate limiting constants
    const RATE_LIMIT_ATTEMPTS = 5;
    const RATE_LIMIT_WINDOW = 300; // 5 minutes

    public function __construct(
        SettingsRepositoryInterface $settings,
        UserRepository $users,
        Dispatcher $events,
        CacheRepository $cache
    ) {
        $this->settings = $settings;
        $this->users = $users;
        $this->events = $events;
        $this->cache = $cache;
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $path = $request->getUri()->getPath();
        
        if (str_contains($path, '/callback')) {
            return $this->callback($request);
        } elseif (str_contains($path, '/logout')) {
            return $this->logout($request);
        } else {
            return $this->login($request);
        }
    }

    public function login(ServerRequestInterface $request): ResponseInterface
    {
        // Rate limiting
        $clientIp = $this->getClientIp($request);
        if (!$this->checkRateLimit($clientIp, 'login')) {
            Log::warning('SSO login rate limit exceeded', ['ip' => $clientIp]);
            throw new ValidationException([
                'message' => 'Too many login attempts. Please try again later.'
            ]);
        }

        $mainSiteUrl = $this->settings->get('jwt-sso.main_site_url');
        $loginUrl = $this->settings->get('jwt-sso.login_url');
        
        if (!$mainSiteUrl || !$loginUrl) {
            Log::error('SSO configuration incomplete');
            throw new ValidationException([
                'message' => 'SSO configuration is incomplete'
            ]);
        }

        // Generate a cryptographically secure state parameter
        $state = bin2hex(random_bytes(32));
        $nonce = bin2hex(random_bytes(16));
        
        $session = $request->getAttribute('session');
        $session->put('jwt_sso_state', $state);
        $session->put('jwt_sso_nonce', $nonce);
        $session->put('jwt_sso_timestamp', time());

        // Build redirect URL with additional security parameters
        $redirectUrl = $loginUrl . '?' . http_build_query([
            'return_url' => $request->getUri()->getScheme() . '://' . 
                          $request->getUri()->getHost() . 
                          '/auth/sso/callback',
            'state' => $state,
            'nonce' => $nonce,
            'timestamp' => time()
        ]);

        Log::info('SSO login initiated', ['ip' => $clientIp]);

        return new RedirectResponse($redirectUrl);
    }

    public function callback(ServerRequestInterface $request): ResponseInterface
    {
        $clientIp = $this->getClientIp($request);
        
        // Rate limiting for callback
        if (!$this->checkRateLimit($clientIp, 'callback')) {
            Log::warning('SSO callback rate limit exceeded', ['ip' => $clientIp]);
            return new RedirectResponse('/?sso_error=rate_limit_exceeded');
        }

        $queryParams = $request->getQueryParams();
        $token = Arr::get($queryParams, 'token');
        $state = Arr::get($queryParams, 'state');
        $error = Arr::get($queryParams, 'error');

        if ($error) {
            Log::info('SSO authentication failed', ['error' => $error, 'ip' => $clientIp]);
            return new RedirectResponse('/?sso_error=' . urlencode($error));
        }

        if (!$token) {
            Log::warning('SSO callback missing token', ['ip' => $clientIp]);
            return new RedirectResponse('/?sso_error=missing_token');
        }

        // Verify state and timing
        $session = $request->getAttribute('session');
        $expectedState = $session->get('jwt_sso_state');
        $expectedNonce = $session->get('jwt_sso_nonce');
        $timestamp = $session->get('jwt_sso_timestamp');
        
        // Check state parameter
        if (!$expectedState || $state !== $expectedState) {
            Log::warning('SSO invalid state parameter', ['ip' => $clientIp]);
            return new RedirectResponse('/?sso_error=invalid_state');
        }

        // Check timestamp (prevent old requests)
        if (!$timestamp || (time() - $timestamp) > 600) { // 10 minutes max
            Log::warning('SSO request too old', ['ip' => $clientIp]);
            return new RedirectResponse('/?sso_error=request_expired');
        }

        // Clear session data
        $session->remove('jwt_sso_state');
        $session->remove('jwt_sso_nonce');
        $session->remove('jwt_sso_timestamp');

        try {
            $userData = $this->verifyAndDecodeToken($token, $expectedNonce);
            $user = $this->createOrUpdateUser($userData);
            
            // Check if user is banned or suspended
            if ($user->is_email_confirmed === false && $this->settings->get('require_email_confirmation')) {
                throw new \Exception('Email confirmation required');
            }

            // Log the user in
            $session->put('user_id', $user->id);
            $session->regenerate(true);

            Log::info('SSO login successful', [
                'user_id' => $user->id,
                'external_id' => $userData['sub'],
                'ip' => $clientIp
            ]);

            return new RedirectResponse('/');
            
        } catch (\Exception $e) {
            Log::error('SSO authentication error', [
                'error' => $e->getMessage(),
                'ip' => $clientIp
            ]);
            return new RedirectResponse('/?sso_error=' . urlencode('authentication_failed'));
        }
    }

    public function logout(ServerRequestInterface $request): ResponseInterface
    {
        $clientIp = $this->getClientIp($request);
        
        $session = $request->getAttribute('session');
        $userId = $session->get('user_id');
        
        $session->forget('user_id');
        $session->regenerate(true);

        Log::info('SSO logout', ['user_id' => $userId, 'ip' => $clientIp]);

        $mainSiteUrl = $this->settings->get('jwt-sso.main_site_url');
        $logoutUrl = $this->settings->get('jwt-sso.logout_url');
        
        if (!$logoutUrl) {
            $logoutUrl = $mainSiteUrl ? $mainSiteUrl . '/logout' : '/';
        }

        return new RedirectResponse($logoutUrl);
    }

    protected function verifyAndDecodeToken(string $token, string $expectedNonce = null): array
    {
        $secretKey = $this->settings->get('jwt-sso.secret_key');
        
        if (!$secretKey) {
            throw new \Exception('JWT secret key not configured');
        }

        try {
            $decoded = JWT::decode($token, new Key($secretKey, 'HS256'));
            $payload = (array) $decoded;

            // Validate required fields
            $requiredFields = ['sub', 'email', 'exp'];
            foreach ($requiredFields as $field) {
                if (!isset($payload[$field])) {
                    throw new \Exception("Missing required field: {$field}");
                }
            }

            // Check if token is expired
            if ($payload['exp'] < time()) {
                throw new \Exception('Token has expired');
            }

            // Validate issuer if configured
            $expectedIssuer = $this->settings->get('jwt-sso.issuer');
            if ($expectedIssuer && (!isset($payload['iss']) || $payload['iss'] !== $expectedIssuer)) {
                throw new \Exception('Invalid token issuer');
            }

            // Validate nonce if provided (prevents replay attacks)
            if ($expectedNonce && (!isset($payload['nonce']) || $payload['nonce'] !== $expectedNonce)) {
                throw new \Exception('Invalid nonce');
            }

            // Check for token reuse (optional)
            $tokenHash = hash('sha256', $token);
            $cacheKey = "jwt_used_{$tokenHash}";
            
            if ($this->cache->has($cacheKey)) {
                throw new \Exception('Token already used');
            }
            
            // Mark token as used (cache until expiration)
            $ttl = max(1, $payload['exp'] - time());
            $this->cache->put($cacheKey, true, $ttl);

            // Validate email format
            if (!filter_var($payload['email'], FILTER_VALIDATE_EMAIL)) {
                throw new \Exception('Invalid email format');
            }

            return $payload;

        } catch (\Firebase\JWT\ExpiredException $e) {
            throw new \Exception('Token has expired');
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            throw new \Exception('Invalid token signature');
        } catch (\Firebase\JWT\BeforeValidException $e) {
            throw new \Exception('Token not yet valid');
        } catch (\Exception $e) {
            throw new \Exception('Invalid token: ' . $e->getMessage());
        }
    }

    protected function createOrUpdateUser(array $userData): User
    {
        $email = trim(strtolower($userData['email']));
        $externalId = $userData['sub'];
        $username = $this->sanitizeUsername($userData['username'] ?? $this->generateUsername($email));
        $displayName = $this->sanitizeDisplayName($userData['name'] ?? $userData['display_name'] ?? $username);

        // Validate data
        if (strlen($username) < 3 || strlen($username) > 30) {
            throw new \Exception('Invalid username length');
        }

        if (strlen($displayName) > 100) {
            $displayName = substr($displayName, 0, 100);
        }

        // Try to find existing user by email first, then by external ID
        $user = $this->users->findByEmail($email);
        
        if (!$user) {
            $user = User::where('jwt_sso_external_id', $externalId)->first();
        }

        if ($user) {
            // Update existing user
            $user->jwt_sso_external_id = $externalId;
            
            // Only update username if it's different and available
            if ($user->username !== $username && !$this->users->findByIdentification($username)) {
                $user->username = $username;
            }
            
            $user->display_name = $displayName;
            $user->email = $email;
            $user->is_email_confirmed = true;
            $user->last_seen_at = now();
            
            // Update avatar if provided and different
            if (!empty($userData['avatar_url']) && filter_var($userData['avatar_url'], FILTER_VALIDATE_URL)) {
                $user->avatar_url = $userData['avatar_url'];
            }
            
            $user->save();
        } else {
            // Ensure username is unique
            $username = $this->ensureUniqueUsername($username);
            
            // Create new user
            $user = User::register($username, $email, null);
            $user->jwt_sso_external_id = $externalId;
            $user->display_name = $displayName;
            $user->is_email_confirmed = true;
            $user->joined_at = now();
            $user->last_seen_at = now();
            
            if (!empty($userData['avatar_url']) && filter_var($userData['avatar_url'], FILTER_VALIDATE_URL)) {
                $user->avatar_url = $userData['avatar_url'];
            }
            
            $user->save();

            // Assign default groups if configured
            $defaultGroups = $this->settings->get('jwt-sso.default_groups');
            if ($defaultGroups) {
                $groupIds = array_filter(array_map('intval', explode(',', $defaultGroups)));
                if (!empty($groupIds)) {
                    $user->groups()->sync($groupIds);
                }
            }
        }

        return $user;
    }

    protected function sanitizeUsername(string $username): string
    {
        // Remove invalid characters and ensure it starts with alphanumeric
        $username = preg_replace('/[^a-zA-Z0-9_-]/', '', $username);
        $username = preg_replace('/^[^a-zA-Z0-9]+/', '', $username);
        
        return $username ?: 'user';
    }

    protected function sanitizeDisplayName(string $displayName): string
    {
        // Remove potentially dangerous characters but keep unicode
        $displayName = trim(preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $displayName));
        
        return $displayName ?: 'User';
    }

    protected function ensureUniqueUsername(string $username): string
    {
        $originalUsername = $username;
        $counter = 1;
        
        while ($this->users->findByIdentification($username)) {
            $username = $originalUsername . $counter;
            $counter++;
            
            // Prevent infinite loop
            if ($counter > 1000) {
                $username = $originalUsername . time();
                break;
            }
        }
        
        return $username;
    }

    protected function generateUsername(string $email): string
    {
        $username = explode('@', $email)[0];
        return $this->sanitizeUsername($username);
    }

    protected function checkRateLimit(string $clientIp, string $action): bool
    {
        $key = "sso_rate_limit_{$action}_{$clientIp}";
        $attempts = $this->cache->get($key, 0);
        
        if ($attempts >= self::RATE_LIMIT_ATTEMPTS) {
            return false;
        }
        
        $this->cache->put($key, $attempts + 1, self::RATE_LIMIT_WINDOW);
        return true;
    }

    protected function getClientIp(ServerRequestInterface $request): string
    {
        $serverParams = $request->getServerParams();
        
        // Check for IP from various headers (in order of preference)
        $headers = [
            'HTTP_CF_CONNECTING_IP',     // Cloudflare
            'HTTP_X_FORWARDED_FOR',      // Load balancer/proxy
            'HTTP_X_REAL_IP',            // Nginx
            'REMOTE_ADDR'                // Standard
        ];
        
        foreach ($headers as $header) {
            if (!empty($serverParams[$header])) {
                $ip = trim(explode(',', $serverParams[$header])[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return $serverParams['REMOTE_ADDR'] ?? 'unknown';
    }
}