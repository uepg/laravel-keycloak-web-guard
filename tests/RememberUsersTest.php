<?php

namespace Uepg\KeycloakWebGuard\Tests;

use Illuminate\Auth\AuthManager;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Uepg\KeycloakWebGuard\Auth\KeycloakWebUserProvider;
use Uepg\KeycloakWebGuard\Models\KeycloakUser;

class RememberUsersTest extends TestCase
{
    protected function tearDown(): void
    {
        KeycloakWebUserProvider::resolveUsersUsing(null);
        parent::tearDown();
    }

    private function provider()
    {
        return Auth::createUserProvider('keycloak-users');
    }

    public function test_retrieve_by_id_returns_null_by_default()
    {
        $this->login();
        Auth::user();

        $this->assertNull($this->provider()->retrieveById('jane@example.com'));
    }

    public function test_user_is_remembered_after_authentication()
    {
        config(['keycloak-web.remember_users' => true]);
        $this->login();
        Auth::user();

        $user = $this->provider()->retrieveById('jane@example.com');

        $this->assertInstanceOf(KeycloakUser::class, $user);
        $this->assertSame('Jane', $user->name);
        $this->assertSame('jane@example.com', $user->id);
        $this->assertNull($this->provider()->retrieveById('other@example.com'));
    }

    public function test_user_is_remembered_once_per_session()
    {
        config(['keycloak-web.remember_users' => true]);
        $this->login();
        Auth::user();
        Cache::forget('keycloak-web-user:jane@example.com');

        // New request, same session
        $this->app->make(AuthManager::class)->forgetGuards();
        Auth::user();

        $this->assertNull($this->provider()->retrieveById('jane@example.com'));
    }

    public function test_profile_change_is_remembered_again()
    {
        config(['keycloak-web.remember_users' => true]);
        $this->login();
        Auth::user();

        $this->routes[self::ISSUER . '/protocol/openid-connect/userinfo'] = fn () => $this->jsonResponse(['sub' => 'user-1', 'name' => 'Jane Doe', 'email' => 'jane@example.com']);
        $this->app->make(AuthManager::class)->forgetGuards();
        Auth::user();

        $this->assertSame('Jane Doe', $this->provider()->retrieveById('jane@example.com')->name);
    }

    public function test_resolver_is_used_for_unknown_users()
    {
        config(['keycloak-web.remember_users' => true]);
        KeycloakWebUserProvider::resolveUsersUsing(fn ($id) => $id === 'bob@example.com' ? ['email' => $id, 'name' => 'Bob'] : null);

        $this->assertSame('Bob', $this->provider()->retrieveById('bob@example.com')->name);
        $this->assertNull($this->provider()->retrieveById('nobody@example.com'));
    }

    public function test_ttl()
    {
        config(['keycloak-web.remember_users' => true, 'keycloak-web.remember_users_ttl' => 60]);
        $this->login();
        Auth::user();

        $this->travel(61)->seconds();

        $this->assertNull($this->provider()->retrieveById('jane@example.com'));
    }
}
