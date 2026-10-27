<?php

namespace Uepg\KeycloakWebGuard\Tests;

use Illuminate\Support\Facades\Auth;
use Uepg\KeycloakWebGuard\Exceptions\KeycloakTokenException;
use Uepg\KeycloakWebGuard\Models\KeycloakUser;

class LegacyNamespaceTest extends TestCase
{
    protected function defineEnvironment($app)
    {
        parent::defineEnvironment($app);

        // Config written for the old package
        $app['config']->set('auth.providers.keycloak-users.model', 'Vizir\KeycloakWebGuard\Models\KeycloakUser');
    }

    public function test_old_class_names_are_aliases()
    {
        $this->assertTrue(class_exists('Vizir\KeycloakWebGuard\Models\KeycloakUser'));
        $this->assertTrue(is_a('Vizir\KeycloakWebGuard\Services\KeycloakService', \Uepg\KeycloakWebGuard\Services\KeycloakService::class, true));
        $this->assertFalse(class_exists('Vizir\KeycloakWebGuard\DoesNotExist'));
    }

    public function test_old_config_model_works()
    {
        $this->login();

        $this->assertInstanceOf(KeycloakUser::class, Auth::user());
        $this->assertInstanceOf('Vizir\KeycloakWebGuard\Models\KeycloakUser', Auth::user());
    }

    public function test_old_subclass_works()
    {
        $user = new LegacyUser(['email' => 'a@b.c']);

        $this->assertInstanceOf(KeycloakUser::class, $user);
        $this->assertSame('a@b.c', $user->id);
    }

    public function test_old_name_on_dont_report()
    {
        \Illuminate\Support\Facades\Log::spy();
        $this->app->make(\Illuminate\Contracts\Debug\ExceptionHandler::class)->dontReport('Vizir\KeycloakWebGuard\Exceptions\KeycloakException');

        report(new KeycloakTokenException('x'));

        \Illuminate\Support\Facades\Log::shouldNotHaveReceived('error');
    }

    public function test_old_exception_can_be_caught()
    {
        try {
            throw new KeycloakTokenException('x');
        } catch (\Vizir\KeycloakWebGuard\Exceptions\KeycloakException $e) {
            $this->assertSame('x', $e->getMessage());
        }
    }
}

class LegacyUser extends \Vizir\KeycloakWebGuard\Models\KeycloakUser
{
}
