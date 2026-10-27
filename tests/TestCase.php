<?php

namespace Uepg\KeycloakWebGuard\Tests;

use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Response;
use Orchestra\Testbench\TestCase as Orchestra;
use Psr\Http\Message\RequestInterface;
use Uepg\KeycloakWebGuard\KeycloakWebGuardServiceProvider;
use Uepg\KeycloakWebGuard\Models\KeycloakUser;
use Uepg\KeycloakWebGuard\Services\KeycloakService;

abstract class TestCase extends Orchestra
{
    const BASE = 'https://kc.test';
    const ISSUER = 'https://kc.test/realms/r';
    const CLIENT = 'app';

    /** @var array<string, string> */
    protected static $keys = [];

    /** @var array<string, callable|Response> Responses by URL (without query) */
    protected $routes = [];

    /** @var RequestInterface[] */
    protected $requests = [];

    protected function getPackageProviders($app)
    {
        return [KeycloakWebGuardServiceProvider::class];
    }

    protected function defineEnvironment($app)
    {
        $app['config']->set('app.key', 'base64:' . base64_encode(str_repeat('k', 32)));
        $app['config']->set('keycloak-web.base_url', self::BASE);
        $app['config']->set('keycloak-web.realm', 'r');
        $app['config']->set('keycloak-web.client_id', self::CLIENT);

        $app['config']->set('auth.defaults.guard', 'keycloak');
        $app['config']->set('auth.guards.keycloak', ['driver' => 'keycloak-web', 'provider' => 'keycloak-users']);
        $app['config']->set('auth.providers.keycloak-users', ['driver' => 'keycloak-users', 'model' => KeycloakUser::class]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->routes = [
            self::ISSUER . '/.well-known/openid-configuration' => fn () => $this->jsonResponse([
                'issuer' => self::ISSUER,
                'authorization_endpoint' => self::ISSUER . '/protocol/openid-connect/auth',
                'token_endpoint' => self::ISSUER . '/protocol/openid-connect/token',
                'userinfo_endpoint' => self::ISSUER . '/protocol/openid-connect/userinfo',
                'end_session_endpoint' => self::ISSUER . '/protocol/openid-connect/logout',
                'jwks_uri' => self::ISSUER . '/protocol/openid-connect/certs',
            ]),
            self::ISSUER . '/protocol/openid-connect/certs' => fn () => $this->jsonResponse(['keys' => [
                self::jwk('kid-1'),
                ['kid' => 'enc', 'kty' => 'RSA', 'alg' => 'RSA-OAEP', 'use' => 'enc', 'n' => 'xx', 'e' => 'AQAB'],
            ]]),
            self::ISSUER . '/protocol/openid-connect/userinfo' => fn () => $this->jsonResponse(['sub' => 'user-1', 'name' => 'Jane', 'email' => 'jane@example.com']),
        ];

        $this->app->instance(KeycloakService::class, $this->makeService());
    }

    protected function makeService()
    {
        $handler = function (RequestInterface $request) {
            $this->requests[] = $request;
            $url = (string) $request->getUri()->withQuery('');
            $response = $this->routes[$url] ?? new Response(404);
            $response = is_callable($response) ? $response($request) : $response;

            return Create::promiseFor($response);
        };

        return new KeycloakService(new Client(['handler' => HandlerStack::create($handler)]));
    }

    protected function jsonResponse($data, $status = 200)
    {
        return new Response($status, ['Content-Type' => 'application/json'], json_encode($data));
    }

    protected function requestsTo($path)
    {
        return count(array_filter($this->requests, fn ($r) => str_ends_with($r->getUri()->getPath(), $path)));
    }

    /**
     * Private key PEM for a kid (generated once per run)
     */
    protected static function privateKey($kid)
    {
        if (empty(self::$keys[$kid])) {
            $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            openssl_pkey_export($key, $pem);
            self::$keys[$kid] = $pem;
        }

        return self::$keys[$kid];
    }

    protected static function publicKey($kid)
    {
        return openssl_pkey_get_details(openssl_pkey_get_private(self::privateKey($kid)))['key'];
    }

    protected static function jwk($kid)
    {
        $rsa = openssl_pkey_get_details(openssl_pkey_get_private(self::privateKey($kid)))['rsa'];
        $b64 = fn ($v) => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');

        return ['kid' => $kid, 'kty' => 'RSA', 'alg' => 'RS256', 'use' => 'sig', 'n' => $b64($rsa['n']), 'e' => $b64($rsa['e'])];
    }

    /**
     * A token set like the one Keycloak returns
     */
    protected function tokens(array $idClaims = [], array $accessClaims = [], $kid = 'kid-1')
    {
        $base = ['iss' => self::ISSUER, 'sub' => 'user-1', 'exp' => time() + 300, 'iat' => time()];

        return [
            'access_token' => JWT::encode(array_merge($base, [
                'azp' => self::CLIENT,
                'resource_access' => [self::CLIENT => ['roles' => ['editor']]],
                'realm_access' => ['roles' => ['member']],
            ], $accessClaims), self::privateKey($kid), 'RS256', $kid),
            'id_token' => JWT::encode(array_merge($base, ['aud' => self::CLIENT], $idClaims), self::privateKey($kid), 'RS256', $kid),
            'refresh_token' => 'refresh',
            'expires_in' => 300,
        ];
    }

    protected function login(?array $tokens = null)
    {
        $this->app['session']->put(KeycloakService::KEYCLOAK_SESSION, $tokens ?? $this->tokens());
    }
}
