<?php

namespace AdityaWiguna\JwtSSO\Controller;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Flarum\Settings\SettingsRepositoryInterface;
use Flarum\User\User;
use Flarum\User\UserRepository;
use Flarum\Http\SessionAuthenticator;
use Flarum\Http\SessionAccessToken;
use Flarum\User\Event\LoggedIn;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Arr;
use Laminas\Diactoros\Response\RedirectResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Carbon\Carbon;
use Psr\Log\LoggerInterface;

class CallbackController implements RequestHandlerInterface
{
    protected $settings;
    protected $users;
    protected $events;
    protected $cache;
    protected $logger;
    protected $authenticator;

    // Rate limiting constants
    const RATE_LIMIT_ATTEMPTS = 10;
    const RATE_LIMIT_WINDOW = 300; // 5 minutes

    public function __construct(
        SettingsRepositoryInterface $settings,
        UserRepository $users,
        Dispatcher $events,
        CacheRepository $cache,
        LoggerInterface $logger,
        SessionAuthenticator $authenticator
    ) {
        $this->settings = $settings;
        $this->users = $users;
        $this->events = $events;
        $this->cache = $cache;
        $this->logger = $logger;
        $this->authenticator = $authenticator;
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $clientIp = $this->getClientIp($request);
        
        // Rate limiting for callback
        if (!$this->checkRateLimit($clientIp, 'callback')) {
            $this->logger->warning('SSO callback rate limit exceeded', ['ip' => $clientIp]);
            return new RedirectResponse('/?sso_error=rate_limit_exceeded');
        }

        $queryParams = $request->getQueryParams();
        $token = Arr::get($queryParams, 'token');
        $state = Arr::get($queryParams, 'state');
        $error = Arr::get($queryParams, 'error');
        $returnUrl = Arr::get($queryParams, 'return_url', '/');

        if ($error) {
            $this->logger->info('SSO authentication failed', ['error' => $error, 'ip' => $clientIp]);
            return new RedirectResponse($returnUrl . '?sso_error=' . urlencode($error));
        }

        if (!$token) {
            $this->logger->warning('SSO callback missing token', ['ip' => $clientIp]);
            return new RedirectResponse($returnUrl . '?sso_error=missing_token');
        }

        $session = $request->getAttribute('session');

        try {
            $userData = $this->verifyAndDecodeToken($token);
            $user = $this->createOrUpdateUser($userData);
            
            // Check if user is banned or suspended
            if ($user->is_email_confirmed === false && $this->settings->get('require_email_confirmation')) {
                throw new \Exception('Email confirmation required');
            }

            // Check if user is suspended
            if ($user->suspended_until && $user->suspended_until->isFuture()) {
                throw new \Exception('User account is suspended');
            }

            // Use Flarum's proper authentication method
            $this->authenticateUser($session, $user, $request);

            $this->logger->info('SSO login successful', [
                'user_id' => $user->id,
                'username' => $user->username,
                'email' => $user->email,
                'external_id' => $userData['sub'],
                'session_id' => $session->getId(),
                'ip' => $clientIp
            ]);

            $accessToken = SessionAccessToken::generate($user->id);
            $this->events->dispatch(
                new LoggedIn($user, $accessToken)
            );
            $this->authenticator->logIn($session, $accessToken);

            // Redirect to the intended URL or home
            return new RedirectResponse('/');
        } catch (\Exception $e) {
            $this->logger->error('SSO authentication error', [
                'error' => $e->getMessage(),
                'token_preview' => substr($token, 0, 20) . '...',
                'ip' => $clientIp,
                'trace' => $e->getTraceAsString()
            ]);
            return new RedirectResponse($returnUrl . '?sso_error=' . urlencode('authentication_failed'));
        }
    }

    /**
     * Authenticate user using multiple methods for maximum compatibility
     */
    protected function authenticateUser($session, User $user, ServerRequestInterface $request): void
    {
        // Method 1: Use SessionAuthenticator if it accepts user object
        try {
            $this->authenticator->logIn($session, $user);
            return;
        } catch (\Throwable $e) {
            $this->logger->debug('SessionAuthenticator method failed', ['error' => $e->getMessage()]);
        }

        // Method 2: Manual session handling with proper Flarum session structure
        $session->put('user_id', $user->id);
        $session->put('csrf_token', bin2hex(random_bytes(20)));
        $session->regenerate(true);
        
        // Update user's last seen time
        $user->last_seen_at = Carbon::now();
        $user->save();

        $this->logger->debug('Used manual session authentication', [
            'user_id' => $user->id,
            'session_id' => $session->getId()
        ]);
    }

    protected function verifyAndDecodeToken(string $token): array
    {
        $secretKey = $this->settings->get('jwt-sso.secret_key');
        
        if (!$secretKey) {
            throw new \Exception('JWT secret key not configured');
        }

        try {
            $decoded = JWT::decode($token, new Key($secretKey, 'HS256'));
            $payload = (array) $decoded;

            // Validate required fields
            $requiredFields = ['sub', 'email'];
            foreach ($requiredFields as $field) {
                if (!isset($payload[$field]) || empty($payload[$field])) {
                    throw new \Exception("Missing or empty required field: {$field}");
                }
            }

            // Check if token is expired (if exp field exists)
            if (isset($payload['exp']) && $payload['exp'] < time()) {
                throw new \Exception('Token has expired');
            }

            // Validate issuer if configured
            $expectedIssuer = $this->settings->get('jwt-sso.issuer');
            if ($expectedIssuer && (!isset($payload['iss']) || $payload['iss'] !== $expectedIssuer)) {
                throw new \Exception('Invalid token issuer');
            }

            // Check for token reuse (optional but recommended)
            $tokenHash = hash('sha256', $token);
            $cacheKey = "jwt_used_{$tokenHash}";
            
            if ($this->cache->has($cacheKey)) {
                throw new \Exception('Token already used');
            }
            
            // Mark token as used (cache until expiration or default 1 hour)
            $ttl = isset($payload['exp']) ? max(1, $payload['exp'] - time()) : 3600;
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
        } catch (\Firebase\JWT\InvalidArgumentException $e) {
            throw new \Exception('Invalid token format');
        } catch (\Exception $e) {
            if (strpos($e->getMessage(), 'Missing or empty required field') === 0 ||
                strpos($e->getMessage(), 'Token') === 0 ||
                strpos($e->getMessage(), 'Invalid') === 0) {
                throw $e;
            }
            throw new \Exception('Token validation failed: ' . $e->getMessage());
        }
    }

    protected function createOrUpdateUser(array $userData): User
    {
        $email = trim(strtolower($userData['email']));
        $externalId = (string) $userData['sub'];
        $username = $this->sanitizeUsername($userData['username'] ?? $this->generateUsername($email));
        $displayName = $this->sanitizeDisplayName($userData['name'] ?? $userData['display_name'] ?? $username);

        // Validate data
        if (strlen($username) < 3 || strlen($username) > 30) {
            $username = $this->generateUsername($email);
            if (strlen($username) < 3) {
                $username = 'user' . substr(md5($email), 0, 8);
            }
        }

        if (strlen($displayName) > 100) {
            $displayName = substr($displayName, 0, 100);
        }

        // Try to find existing user by external ID first, then by email
        $user = User::where('jwt_sso_external_id', $externalId)->first();
        
        if (!$user) {
            $user = $this->users->findByEmail($email);
        }

        if ($user) {
            // Update existing user
            $user->jwt_sso_external_id = $externalId;
            
            // Only update username if it's different and available
            if ($user->username !== $username && !$this->users->findByIdentification($username)) {
                $user->username = $username;
            }
            
            // Update email if different
            if ($user->email !== $email) {
                $user->email = $email;
            }
            
            $user->is_email_confirmed = true;
            $user->last_seen_at = Carbon::now();
            
            // Update avatar if provided and different
            if (!empty($userData['avatar_url']) && filter_var($userData['avatar_url'], FILTER_VALIDATE_URL)) {
                if ($user->avatar_url !== $userData['avatar_url']) {
                    $user->avatar_url = $userData['avatar_url'];
                }
            }
            
            $user->save();

            $this->logger->debug('Updated existing user', [
                'user_id' => $user->id,
                'username' => $user->username,
                'email' => $user->email
            ]);
        } else {
            // Ensure username is unique
            $username = $this->ensureUniqueUsername($username);
            
            // Create new user
            $user = User::register($username, $email, null);
            $user->jwt_sso_external_id = $externalId;
            $user->is_email_confirmed = true;
            $user->joined_at = Carbon::now();
            $user->last_seen_at = Carbon::now();
            
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

            $this->logger->info('Created new user', [
                'user_id' => $user->id,
                'username' => $user->username,
                'email' => $user->email,
                'external_id' => $externalId
            ]);
        }

        return $user;
    }

    protected function sanitizeUsername(string $username): string
    {
        // Remove invalid characters and ensure it starts with alphanumeric
        $username = preg_replace('/[^a-zA-Z0-9_-]/', '', $username);
        $username = preg_replace('/^[^a-zA-Z0-9]+/', '', $username);
        $username = trim($username);
        
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
                $username = $originalUsername . substr(md5(time()), 0, 6);
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

    protected function sanitizeReturnUrl(string $returnUrl): string
    {
        // Ensure return URL is safe and relative
        $returnUrl = trim($returnUrl);
        
        // If empty, default to home
        if (empty($returnUrl)) {
            return '/';
        }
        
        // Parse URL to check if it's relative or from same domain
        $parsed = parse_url($returnUrl);
        
        // If it's a full URL, check if it's from the same domain
        if (isset($parsed['scheme']) && isset($parsed['host'])) {
            $forumUrl = $this->settings->get('url');
            $forumHost = parse_url($forumUrl, PHP_URL_HOST);
            
            if ($parsed['host'] !== $forumHost) {
                return '/'; // Redirect to home if external domain
            }
        }
        
        // If it's relative, ensure it starts with /
        if (!isset($parsed['scheme']) && !isset($parsed['host'])) {
            if (!str_starts_with($returnUrl, '/')) {
                $returnUrl = '/' . $returnUrl;
            }
        }
        
        return $returnUrl;
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
            'HTTP_CLIENT_IP',            // Proxy
            'REMOTE_ADDR'                // Standard
        ];
        
        foreach ($headers as $header) {
            if (!empty($serverParams[$header])) {
                $ips = explode(',', $serverParams[$header]);
                $ip = trim($ips[0]);
                
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
                
                // If public IP validation fails, use the IP anyway if it's valid
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return $serverParams['REMOTE_ADDR'] ?? 'unknown';
    }
}