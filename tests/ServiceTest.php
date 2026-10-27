<?php

namespace Uepg\KeycloakWebGuard\Tests;

use Illuminate\Support\Facades\Exceptions;
use Uepg\KeycloakWebGuard\Auth\KeycloakAccessToken;
use Uepg\KeycloakWebGuard\Exceptions\KeycloakTokenException;
use Uepg\KeycloakWebGuard\Services\KeycloakService;

class ServiceTest extends TestCase
{
    public function test_valid_tokens_return_profile()
    {
        Exceptions::fake();

        $user = app(KeycloakService::class)->getUserProfile($this->tokens());

        $this->assertSame('jane@example.com', $user['email']);
        Exceptions::assertNothingReported();
    }

    public function test_sub_mismatch_is_rejected()
    {
        Exceptions::fake();
        $this->routes[self::ISSUER . '/protocol/openid-connect/userinfo'] = fn () => $this->jsonResponse(['sub' => 'someone-else', 'email' => 'x@example.com']);

        $this->assertSame([], app(KeycloakService::class)->getUserProfile($this->tokens()));
        Exceptions::assertReported(fn (KeycloakTokenException $e) => str_contains($e->getMessage(), 'sub'));
    }

    public function test_signature_from_another_key_is_rejected()
    {
        Exceptions::fake();
        // Signed with an unknown key, but claiming the published kid
        $tokens = $this->tokens([], [], 'attacker');
        $tokens['id_token'] = $this->reKid($tokens['id_token']);
        $tokens['access_token'] = $this->reKid($tokens['access_token']);

        $this->assertSame([], app(KeycloakService::class)->getUserProfile($tokens));
        Exceptions::assertReported(fn (KeycloakTokenException $e) => str_contains($e->getMessage(), 'signature'));
    }

    public function test_verification_can_be_disabled()
    {
        config(['keycloak-web.verify_signature' => false]);
        $tokens = $this->tokens([], [], 'attacker');

        $this->assertNotEmpty($this->makeService()->getUserProfile($tokens));
        $this->assertSame(0, $this->requestsTo('/certs'));
    }

    public function test_realm_public_key_is_used_instead_of_jwks()
    {
        $pem = self::publicKey('kid-1');
        $body = trim(str_replace(['-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----', "\n"], '', $pem));
        config(['keycloak-web.realm_public_key' => $body]);

        $this->assertNotEmpty($this->makeService()->getUserProfile($this->tokens()));
        $this->assertSame(0, $this->requestsTo('/certs'));
    }

    public function test_rotated_key_refetches_cached_jwks()
    {
        config(['keycloak-web.cache_openid' => true]);
        $this->assertNotEmpty($this->makeService()->getUserProfile($this->tokens()));
        $this->assertSame(1, $this->requestsTo('/certs'));

        // Keycloak rotates to kid-2
        $this->routes[self::ISSUER . '/protocol/openid-connect/certs'] = fn () => $this->jsonResponse(['keys' => [self::jwk('kid-2')]]);

        $this->assertNotEmpty($this->makeService()->getUserProfile($this->tokens([], [], 'kid-2')));
        $this->assertSame(2, $this->requestsTo('/certs'));
    }

    public function test_profile_cache_skips_userinfo_while_token_is_the_same()
    {
        config(['keycloak-web.cache_user_profile' => true]);
        $service = $this->makeService();
        $tokens = $this->tokens();

        $service->getUserProfile($tokens);
        $service->getUserProfile($tokens);
        $this->assertSame(1, $this->requestsTo('/userinfo'));

        $service->getUserProfile($this->tokens([], ['jti' => 'new']));
        $this->assertSame(2, $this->requestsTo('/userinfo'));
    }

    public function test_openid_cache_has_ttl()
    {
        config(['keycloak-web.cache_openid' => true, 'keycloak-web.cache_openid_ttl' => 10]);
        $this->makeService()->getLoginUrl();
        $this->makeService()->getLoginUrl();
        $this->assertSame(1, $this->requestsTo('/openid-configuration'));

        $this->travel(11)->seconds();
        $this->makeService()->getLoginUrl();
        $this->assertSame(2, $this->requestsTo('/openid-configuration'));
    }

    public function test_malformed_tokens_are_parsed_as_empty()
    {
        $this->assertSame([], (new KeycloakAccessToken(['access_token' => 'nodots']))->parseAccessToken());
        $this->assertSame([], (new KeycloakAccessToken(['access_token' => 'a.%%%.c']))->parseAccessToken());
    }

    public function test_base64url_without_padding()
    {
        $payload = rtrim(strtr(base64_encode('{"sub":"ab"}'), '+/', '-_'), '=');
        $token = new KeycloakAccessToken(['access_token' => "h.$payload.s"]);

        $this->assertSame(['sub' => 'ab'], $token->parseAccessToken());
    }

    private function reKid($jwt)
    {
        [$header, $payload, $signature] = explode('.', $jwt);
        $header = json_decode(base64_decode(strtr($header, '-_', '+/')), true);
        $header['kid'] = 'kid-1';

        return rtrim(strtr(base64_encode(json_encode($header)), '+/', '-_'), '=') . ".$payload.$signature";
    }
}
