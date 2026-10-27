<?php

namespace Uepg\KeycloakWebGuard;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use Uepg\KeycloakWebGuard\Auth\Guard\KeycloakWebGuard;
use Uepg\KeycloakWebGuard\Auth\KeycloakWebUserProvider;
use Uepg\KeycloakWebGuard\Middleware\KeycloakAuthenticated;
use Uepg\KeycloakWebGuard\Middleware\KeycloakCan;
use Uepg\KeycloakWebGuard\Middleware\KeycloakCanOne;
use Uepg\KeycloakWebGuard\Services\KeycloakService;

class KeycloakWebGuardServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        // Configuration
        $this->publishes([__DIR__ . '/../config/keycloak-web.php' => config_path('keycloak-web.php')], 'config');

        // User Provider
        Auth::provider('keycloak-users', function($app, array $config) {
            return new KeycloakWebUserProvider($config['model']);
        });

        // Keycloak Web Guard
        Auth::extend('keycloak-web', function ($app, $name, array $config) {
            $provider = Auth::createUserProvider($config['provider']);
            return new KeycloakWebGuard($provider, $app->request, $name);
        });

        // Gate
        Gate::define('keycloak-web', function ($user, $roles, $resource = '') {
            return $user->hasRole($roles, $resource) ?: null;
        });

        // Routes
        if (! $this->app->routesAreCached()) {
            $this->registerRoutes();
        }

        // Middleware Group
        $this->app['router']->middlewareGroup('keycloak-web', [
            StartSession::class,
            KeycloakAuthenticated::class,
        ]);

        // Add Middleware "keycloak-web-can"
        $this->app['router']->aliasMiddleware('keycloak-web-can', KeycloakCan::class);

        // Add Middleware "keycloak-web-can-any" ("keycloak-web-can-one" is kept for backwards compatibility)
        $this->app['router']->aliasMiddleware('keycloak-web-can-any', KeycloakCanOne::class);
        $this->app['router']->aliasMiddleware('keycloak-web-can-one', KeycloakCanOne::class);
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/keycloak-web.php', 'keycloak-web');

        // One instance per request: the state generated for login must be the one saved in session
        $this->app->scoped(KeycloakService::class);

        // Facades
        $this->app->alias(KeycloakService::class, 'keycloak-web');

        // Bind for client data
        $this->app->when(KeycloakService::class)->needs(ClientInterface::class)->give(function() {
            return new Client(Config::get('keycloak-web.guzzle_options', []));
        });
    }

    /**
     * Register the authentication routes for keycloak.
     *
     * @return void
     */
    private function registerRoutes()
    {
        $defaults = [
            'login' => 'login',
            'logout' => 'logout',
            'register' => 'register',
            'callback' => 'callback',
        ];

        $routes = Config::get('keycloak-web.routes', []);
        $routes = array_merge($defaults, $routes);

        $controller = 'Uepg\KeycloakWebGuard\Controllers\AuthController';

        // Register Routes
        $router = $this->app->make('router');

        if (! empty($routes['login'])) {
            $router->middleware('web')->get($routes['login'], $controller . '@login')->name('keycloak.login');
        }

        if (! empty($routes['logout'])) {
            $methods = array_map('strtoupper', (array) Config::get('keycloak-web.logout_methods', ['GET']));
            $router->middleware('web')->match($methods, $routes['logout'], $controller . '@logout')->name('keycloak.logout');
        }

        if (! empty($routes['register'])) {
            $router->middleware('web')->get($routes['register'], $controller . '@register')->name('keycloak.register');
        }

        if (! empty($routes['callback'])) {
            $router->middleware('web')->get($routes['callback'], $controller . '@callback')->name('keycloak.callback');
        }
    }
}
