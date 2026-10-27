<?php

namespace Uepg\KeycloakWebGuard\Tests;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Log;
use Uepg\KeycloakWebGuard\Exceptions\KeycloakException;
use Uepg\KeycloakWebGuard\Exceptions\KeycloakRequestException;
use Uepg\KeycloakWebGuard\Exceptions\KeycloakTokenException;
use Uepg\KeycloakWebGuard\Services\KeycloakService;

class ReportTest extends TestCase
{
    private function tokenEndpointReturns($response)
    {
        $this->routes[self::ISSUER . '/protocol/openid-connect/token'] = $response;
    }

    public function test_guzzle_error_is_reported_as_keycloak_exception()
    {
        Exceptions::fake();
        $this->tokenEndpointReturns(new Response(400, [], '{"error":"invalid_grant"}'));

        $this->assertSame([], app(KeycloakService::class)->getAccessToken('code'));

        Exceptions::assertReported(function (KeycloakRequestException $e) {
            return $e->context() === [
                'method' => 'POST',
                'url' => self::ISSUER . '/protocol/openid-connect/token',
                'status' => 400,
                'response' => '{"error":"invalid_grant"}',
            ];
        });
    }

    public function test_connect_error_without_response()
    {
        Exceptions::fake();
        $this->tokenEndpointReturns(fn ($r) => throw new ConnectException('down', $r));

        app(KeycloakService::class)->getAccessToken('code');

        Exceptions::assertReported(fn (KeycloakRequestException $e) => ! isset($e->context()['status']));
    }

    public function test_invalid_profile_is_reported()
    {
        Exceptions::fake();

        $this->assertSame([], app(KeycloakService::class)->getUserProfile(['access_token' => 'x']));

        Exceptions::assertReported(KeycloakTokenException::class);
    }

    public function test_openid_failure_throws()
    {
        $this->routes = [];
        $this->expectException(KeycloakRequestException::class);

        app(KeycloakService::class)->getLoginUrl();
    }

    public function test_dont_report_silences_logs()
    {
        Log::spy();
        $this->app->make(ExceptionHandler::class)->dontReport(KeycloakException::class);
        $this->tokenEndpointReturns(new Response(400, [], 'x'));

        app(KeycloakService::class)->getAccessToken('code');

        Log::shouldNotHaveReceived('error');
    }

    public function test_logged_by_default_with_context_and_no_headers()
    {
        Log::spy();
        $this->tokenEndpointReturns(new Response(400, [], 'boom'));

        app(KeycloakService::class)->getAccessToken('code');

        Log::shouldHaveReceived('error')->withArgs(function ($message, $context) {
            return str_contains($message, '[Keycloak Service]')
                && $context['status'] === 400
                && $context['response'] === 'boom'
                && ! str_contains(json_encode($context), 'Bearer');
        })->once();
    }
}
