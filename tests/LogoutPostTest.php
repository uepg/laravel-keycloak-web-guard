<?php

namespace Uepg\KeycloakWebGuard\Tests;

class LogoutPostTest extends TestCase
{
    protected function defineEnvironment($app)
    {
        parent::defineEnvironment($app);
        $app['config']->set('keycloak-web.logout_methods', ['post']);
    }

    public function test_logout_only_accepts_post()
    {
        $this->get('/logout')->assertStatus(405);
        $this->withoutMiddleware(\Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class)
            ->post('/logout')->assertRedirect();
    }
}
