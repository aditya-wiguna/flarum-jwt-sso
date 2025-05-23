<?php

namespace AdityaWiguna\JwtSSO\Controller;

use Flarum\Settings\SettingsRepositoryInterface;
use Illuminate\Support\Facades\Log;
use Laminas\Diactoros\Response\RedirectResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class LogoutController implements RequestHandlerInterface
{
    protected $settings;

    public function __construct(SettingsRepositoryInterface $settings)
    {
        $this->settings = $settings;
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
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