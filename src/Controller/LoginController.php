<?php

namespace AdityaWiguna\JwtSSO\Controller;

use Flarum\Foundation\ValidationException;
use Flarum\Settings\SettingsRepositoryInterface;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Log;
use Laminas\Diactoros\Response\RedirectResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class LoginController implements RequestHandlerInterface
{
    protected $settings;
    protected $cache;

    // Rate limiting constants
    const RATE_LIMIT_ATTEMPTS = 5;
    const RATE_LIMIT_WINDOW = 300; // 5 minutes

    public function __construct(
        SettingsRepositoryInterface $settings,
        CacheRepository $cache
    ) {
        $this->settings = $settings;
        $this->cache = $cache;
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        // Rate limiting
        $clientIp = $this->getClientIp($request);
        //TODO: Enable rate limiting
        // if (!$this->checkRateLimit($clientIp, 'login')) {
        //     Log::warning('SSO login rate limit exceeded', ['ip' => $clientIp]);
        //     throw new ValidationException([
        //         'message' => 'Too many login attempts. Please try again later.'
        //     ]);
        // }

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

        //Log::info('SSO login initiated', ['ip' => $clientIp]);

        return new RedirectResponse($redirectUrl);
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