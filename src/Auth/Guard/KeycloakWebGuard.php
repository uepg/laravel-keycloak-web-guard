<?php

namespace Uepg\KeycloakWebGuard\Auth\Guard;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Uepg\KeycloakWebGuard\Auth\KeycloakAccessToken;
use Uepg\KeycloakWebGuard\Auth\KeycloakWebUserProvider;
use Uepg\KeycloakWebGuard\Models\KeycloakUser;
use Uepg\KeycloakWebGuard\Facades\KeycloakWeb;
use Illuminate\Contracts\Auth\UserProvider;

class KeycloakWebGuard implements Guard
{
    /**
     * Session key to remember users only once per session (or when profile changes)
     */
    public const REMEMBERED_SESSION = '_keycloak_remembered';

    /**
     * @var null|Authenticatable|KeycloakUser
     */
    protected $user;

    /**
     * @var UserProvider
     */
    protected $provider;

    /**
     * @var Request
     */
    protected $request;

    /**
     * Avoid recursion: reporting an error during authentication makes
     * Laravel's exception handler call Auth::id() again.
     *
     * @var bool
     */
    protected $authenticating = false;

    /**
     * The guard name
     *
     * @var string|null
     */
    protected $name;

    public function __construct(UserProvider $provider, Request $request, $name = null)
    {
        $this->provider = $provider;
        $this->request = $request;
        $this->name = $name;
    }

    /**
     * Get the guard name
     *
     * @return string
     */
    public function getName()
    {
        return $this->name ?: Auth::getDefaultDriver();
    }

    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check()
    {
        return (bool) $this->user();
    }

    /**
     * @return bool
     */
    public function hasUser()
    {
        return (bool) $this->user;
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest()
    {
        return ! $this->check();
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if (empty($this->user)) {
            $this->authenticate();
        }

        return $this->user;
    }

    /**
     * Set the current user.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @return void
     */
    public function setUser(?Authenticatable $user)
    {
        $this->user = $user;
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|string|null
     */
    public function id()
    {
        $user = $this->user();
        return $user->id ?? null;
    }

    /**
    * Disable viaRemember methode used by some bundles (like filament)
    *
    * @return bool
    */
    public function viaRemember()
    {
        return false;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     *
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        if (empty($credentials['access_token']) || empty($credentials['id_token'])) {
            return false;
        }

        /**
         * Store the section
         */
        $credentials['refresh_token'] = $credentials['refresh_token'] ?? '';
        KeycloakWeb::saveToken($credentials);

        return $this->authenticate();
    }

    /**
     * Try to authenticate the user
     *
     * Errors are reported by KeycloakService, so we just return false here
     * and let the app redirect to login.
     *
     * @return bool
     */
    public function authenticate()
    {
        if ($this->authenticating) {
            return false;
        }

        $this->authenticating = true;

        try {
            return $this->attemptAuthentication();
        } finally {
            $this->authenticating = false;
        }
    }

    /**
     * Retrieve the user from Keycloak using the token in session
     *
     * @return bool
     */
    protected function attemptAuthentication()
    {
        // Get Credentials
        $credentials = KeycloakWeb::retrieveToken();
        if (empty($credentials)) {
            return false;
        }

        $user = KeycloakWeb::getUserProfile($credentials);
        if (empty($user)) {
            KeycloakWeb::forgetToken();

            return false;
        }

        // Provide User
        $profile = $user;
        $user = $this->provider->retrieveByCredentials($profile);
        if (empty($user)) {
            return false;
        }

        $this->setUser($user);
        $this->rememberUser($user, $profile);

        event(new Authenticated($this->getName(), $user));

        return true;
    }

    /**
     * Remember the user profile once per session (see KeycloakWebUserProvider::retrieveById)
     *
     * @param  Authenticatable $user
     * @param  array $profile
     * @return void
     */
    protected function rememberUser(Authenticatable $user, array $profile)
    {
        if (! Config::get('keycloak-web.remember_users', false) || ! $this->provider instanceof KeycloakWebUserProvider) {
            return;
        }

        $session = $this->request->hasSession() ? $this->request->session() : session();
        $hash = hash('sha256', json_encode($profile));

        if ($session->get(self::REMEMBERED_SESSION) === $hash) {
            return;
        }

        $this->provider->rememberUser($user, $profile);
        $session->put(self::REMEMBERED_SESSION, $hash);
    }

    /**
     * Check user is authenticated and return his resource roles
     *
     * @param string $resource Default is empty: point to client_id
     *
     * @return array Empty when user is not authenticated
     */
    public function roles($resource = '')
    {
        if (empty($resource)) {
            $resource = Config::get('keycloak-web.client_id');
        }

        if (! $this->check()) {
            return [];
        }

        $token = KeycloakWeb::retrieveToken();

        if (empty($token) || empty($token['access_token'])) {
            return [];
        }

        $token = new KeycloakAccessToken($token);
        $token = $token->parseAccessToken();

        $resourceRoles = $token['resource_access'] ?? [];
        $resourceRoles = $resourceRoles[ $resource ] ?? [];
        $resourceRoles = $resourceRoles['roles'] ?? [];

        $realmRoles = $token['realm_access'] ?? [];
        $realmRoles = $realmRoles['roles'] ?? [];

        return array_values(array_unique(array_merge($resourceRoles, $realmRoles)));
    }

    /**
     * Check user has a role
     *
     * @param array|string $roles
     * @param string $resource Default is empty: point to client_id
     *
     * @return bool
     */
    public function hasRole($roles, $resource = '')
    {
        if (! $this->check()) {
            return false;
        }

        return empty(array_diff((array) $roles, $this->roles($resource)));
    }
}
