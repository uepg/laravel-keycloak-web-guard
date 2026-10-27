<?php

namespace Uepg\KeycloakWebGuard\Tests;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Logout;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Uepg\KeycloakWebGuard\Models\KeycloakUser;

class GuardTest extends TestCase
{
    protected function defineRoutes($router)
    {
        $router->middleware(['web', 'keycloak-web-can:editor'])->get('/editor', fn () => 'ok');
        $router->middleware(['web', 'keycloak-web-can:admin'])->get('/admin-only', fn () => 'ok');
        $router->middleware(['web', 'keycloak-web-can-one:admin|member'])->get('/one', fn () => 'ok');
        $router->middleware(['web', 'keycloak-web-can-any:admin|member'])->get('/any', fn () => 'ok');
        $router->middleware(['web', 'keycloak-web-can-any:admin|owner'])->get('/any-forbidden', fn () => 'ok');
        $router->middleware(['web', 'keycloak-web'])->get('/private', fn () => Auth::id());
    }

    public function test_user_id_is_the_email()
    {
        $user = new KeycloakUser(['sub' => 'user-1', 'email' => 'jane@example.com', 'name' => 'Jane']);

        $this->assertSame('jane@example.com', $user->id);
        $this->assertSame('jane@example.com', $user->getAuthIdentifier());
        $this->assertSame('user-1', $user->sub);
        $this->assertTrue(isset($user->email));
        $this->assertFalse(isset($user->nickname));
    }

    public function test_auth_id_works()
    {
        $this->login();

        $this->assertSame('jane@example.com', Auth::id());
    }

    public function test_guest_on_can_route_is_redirected_to_login()
    {
        $this->get('/editor')->assertRedirect(route('keycloak.login'));
        $this->get('/one')->assertRedirect(route('keycloak.login'));
        $this->get('/any')->assertRedirect(route('keycloak.login'));
    }

    public function test_roles()
    {
        $tokens = $this->tokens();

        $this->withSession(['_keycloak_token' => $tokens])->get('/editor')->assertOk();
        $this->withSession(['_keycloak_token' => $tokens])->get('/admin-only')->assertForbidden();
        $this->withSession(['_keycloak_token' => $tokens])->get('/one')->assertOk();
        $this->withSession(['_keycloak_token' => $tokens])->get('/any')->assertOk();
        $this->withSession(['_keycloak_token' => $tokens])->get('/any-forbidden')->assertForbidden();
        $this->withSession(['_keycloak_token' => $tokens])->get('/private')->assertSee('jane@example.com');
    }

    public function test_guest_has_no_roles()
    {
        $this->assertSame([], Auth::roles());
        $this->assertFalse(Auth::hasRole([]));
        $this->assertFalse(Auth::hasRole(''));
    }

    public function test_invalid_session_in_debug_redirects_instead_of_throwing()
    {
        config(['app.debug' => true]);
        $tokens = $this->tokens(['aud' => 'other-client']);

        $this->withSession(['_keycloak_token' => $tokens])->get('/private')->assertRedirect(route('keycloak.login'));
    }

    public function test_authenticated_event_uses_guard_name()
    {
        Event::fake([Authenticated::class]);
        $this->login();

        Auth::user();

        Event::assertDispatched(Authenticated::class, fn ($e) => $e->guard === 'keycloak' && $e->user->email === 'jane@example.com');
    }

    public function test_logout_event_has_user()
    {
        Event::fake([Logout::class]);

        $this->withSession(['_keycloak_token' => $this->tokens()])->get('/logout')->assertRedirect();

        Event::assertDispatched(Logout::class, fn ($e) => $e->guard === 'keycloak' && $e->user->email === 'jane@example.com');
    }
}
