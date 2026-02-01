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
use Laminas\Diactoros\Response\HtmlResponse;
use Laminas\Diactoros\Response\RedirectResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Carbon\Carbon;
use Psr\Log\LoggerInterface;

/**
 * Handles OAuth callback in popup window
 * Authenticates user and closes popup, telling parent window to reload
 */
class PopupCallbackController implements RequestHandlerInterface
{
    protected $settings;
    protected $users;
    protected $events;
    protected $cache;
    protected $logger;
    protected $authenticator;

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
        $queryParams = $request->getQueryParams();
        $token = Arr::get($queryParams, 'token');
        $state = Arr::get($queryParams, 'state');
        $error = Arr::get($queryParams, 'sso_error');

        // If there's an error, show error page that closes popup
        if ($error) {
            return $this->renderPopupResponse(false, $error);
        }

        if (!$token) {
            return $this->renderPopupResponse(false, 'missing_token');
        }

        $session = $request->getAttribute('session');

        try {
            $userData = $this->verifyAndDecodeToken($token);
            $user = $this->createOrUpdateUser($userData);
            
            // Check if user is suspended
            if ($user->suspended_until && $user->suspended_until->isFuture()) {
                throw new \Exception('User account is suspended');
            }

            // Authenticate user
            $accessToken = SessionAccessToken::generate($user->id);
            $this->events->dispatch(new LoggedIn($user, $accessToken));
            $this->authenticator->logIn($session, $accessToken);

            $this->logger->info('SSO popup login successful', [
                'user_id' => $user->id,
                'username' => $user->username,
                'email' => $user->email
            ]);

            // Return HTML that closes popup and reloads parent
            return $this->renderPopupResponse(true);

        } catch (\Exception $e) {
            $this->logger->error('SSO popup authentication error', [
                'error' => $e->getMessage()
            ]);
            return $this->renderPopupResponse(false, 'authentication_failed');
        }
    }

    /**
     * Render HTML response that handles popup close and parent reload
     */
    protected function renderPopupResponse(bool $success, string $error = null): ResponseInterface
    {
        $forumUrl = $this->settings->get('url') ?: '';
        
        if ($success) {
            $html = <<<HTML
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Successful</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
        .success { color: #28a745; font-size: 24px; margin-bottom: 20px; }
        .message { color: #666; }
    </style>
</head>
<body>
    <div class="success">✓ Đăng nhập thành công!</div>
    <div class="message">Đang chuyển hướng...</div>
    <script>
        (function() {
            try {
                // Try to reload parent window
                if (window.opener && !window.opener.closed) {
                    window.opener.location.reload();
                }
            } catch (e) {
                console.error('Could not reload parent:', e);
            }
            
            // Close this popup
            setTimeout(function() {
                window.close();
                
                // If popup didn't close (some browsers block this), redirect
                setTimeout(function() {
                    window.location.href = '{$forumUrl}';
                }, 500);
            }, 500);
        })();
    </script>
</body>
</html>
HTML;
        } else {
            $errorMessage = $this->getErrorMessage($error);
            $html = <<<HTML
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Failed</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
        .error { color: #dc3545; font-size: 24px; margin-bottom: 20px; }
        .message { color: #666; margin-bottom: 20px; }
        .button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; }
    </style>
</head>
<body>
    <div class="error">✗ Đăng nhập thất bại</div>
    <div class="message">{$errorMessage}</div>
    <a href="javascript:window.close();" class="button">Đóng</a>
    <script>
        setTimeout(function() {
            window.close();
        }, 5000);
    </script>
</body>
</html>
HTML;
        }

        return new HtmlResponse($html);
    }

    protected function getErrorMessage(string $error = null): string
    {
        $messages = [
            'missing_token' => 'Không nhận được token xác thực',
            'authentication_failed' => 'Xác thực thất bại. Vui lòng thử lại.',
            'invalid_state' => 'Phiên đăng nhập không hợp lệ',
            'rate_limit_exceeded' => 'Quá nhiều yêu cầu. Vui lòng thử lại sau.',
        ];

        return $messages[$error] ?? 'Đã xảy ra lỗi. Vui lòng thử lại.';
    }

    protected function verifyAndDecodeToken(string $token): array
    {
        $secretKey = $this->settings->get('jwt-sso.secret_key');
        
        if (!$secretKey) {
            throw new \Exception('JWT secret key not configured');
        }

        $decoded = JWT::decode($token, new Key($secretKey, 'HS256'));
        $payload = (array) $decoded;

        // Validate required fields
        if (!isset($payload['sub']) || !isset($payload['email'])) {
            throw new \Exception('Missing required fields');
        }

        // Check expiration
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            throw new \Exception('Token expired');
        }

        // Check token reuse
        $tokenHash = hash('sha256', $token);
        $cacheKey = "jwt_used_{$tokenHash}";
        
        if ($this->cache->has($cacheKey)) {
            throw new \Exception('Token already used');
        }
        
        $ttl = isset($payload['exp']) ? max(1, $payload['exp'] - time()) : 3600;
        $this->cache->put($cacheKey, true, $ttl);

        return $payload;
    }

    protected function createOrUpdateUser(array $userData): User
    {
        $email = trim(strtolower($userData['email']));
        $externalId = (string) $userData['sub'];
        $username = $this->sanitizeUsername($userData['username'] ?? $this->generateUsername($email));

        // Find existing user
        $user = User::where('jwt_sso_external_id', $externalId)->first();
        
        if (!$user) {
            $user = $this->users->findByEmail($email);
        }

        if ($user) {
            $user->jwt_sso_external_id = $externalId;
            $user->is_email_confirmed = true;
            $user->last_seen_at = Carbon::now();
            
            if (!empty($userData['avatar_url'])) {
                $user->avatar_url = $userData['avatar_url'];
            }
            
            $user->save();
        } else {
            $username = $this->ensureUniqueUsername($username);
            
            $user = User::register($username, $email, null);
            $user->jwt_sso_external_id = $externalId;
            $user->is_email_confirmed = true;
            $user->joined_at = Carbon::now();
            $user->last_seen_at = Carbon::now();
            
            if (!empty($userData['avatar_url'])) {
                $user->avatar_url = $userData['avatar_url'];
            }
            
            $user->save();

            // Assign default groups
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
        $username = preg_replace('/[^a-zA-Z0-9_-]/', '', $username);
        $username = preg_replace('/^[^a-zA-Z0-9]+/', '', $username);
        return trim($username) ?: 'user';
    }

    protected function ensureUniqueUsername(string $username): string
    {
        $original = $username;
        $counter = 1;
        
        while ($this->users->findByIdentification($username)) {
            $username = $original . $counter++;
            if ($counter > 1000) {
                $username = $original . substr(md5(time()), 0, 6);
                break;
            }
        }
        
        return $username;
    }

    protected function generateUsername(string $email): string
    {
        return $this->sanitizeUsername(explode('@', $email)[0]);
    }
}