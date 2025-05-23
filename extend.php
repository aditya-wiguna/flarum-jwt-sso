<?php

use Flarum\Extend;
use AdityaWiguna\JwtSSO\Controller\LoginController;
use AdityaWiguna\JwtSSO\Controller\CallbackController;
use AdityaWiguna\JwtSSO\Controller\LogoutController;

return [
    (new Extend\Frontend('forum'))
        ->js(__DIR__.'/js/dist/forum.js'),

    (new Extend\Frontend('admin'))
        ->js(__DIR__.'/js/dist/admin.js'),

    new Extend\Locales(__DIR__.'/locale'),

    (new Extend\Routes('forum'))
        ->get('/auth/sso/login', 'jwt-sso.login', LoginController::class)
        ->get('/auth/sso/callback', 'jwt-sso.callback', CallbackController::class)
        ->post('/auth/sso/logout', 'jwt-sso.logout', LogoutController::class),

    (new Extend\Settings())
        ->serializeToForum('jwt-sso.mainSiteUrl', 'jwt-sso.main_site_url')
        ->serializeToForum('jwt-sso.loginUrl', 'jwt-sso.login_url'),
];