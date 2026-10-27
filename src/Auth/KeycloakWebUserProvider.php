<?php

namespace Uepg\KeycloakWebGuard\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;

class KeycloakWebUserProvider implements UserProvider
{
    /**
     * The user model.
     *
     * @var string
     */
    protected $model;

    /**
     * Custom resolver for retrieveById()
     *
     * @var callable|null
     */
    protected static $userResolver;

    /**
     * The Constructor
     *
     * @param string $model
     */
    public function __construct($model)
    {
        $this->model = $model;
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array  $credentials
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByCredentials(array $credentials)
    {
        $class = '\\'.ltrim($this->model, '\\');

        return new $class($credentials);
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * We can't ask Keycloak about a user without its token, so this works
     * only for users remembered on login ("remember_users" config) or through
     * a resolver registered with resolveUsersUsing(). It's used by packages
     * like Laravel Pulse to show users that are not logged in.
     *
     * @param  mixed  $identifier
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveById($identifier)
    {
        if (is_null($identifier) || $identifier === '') {
            return null;
        }

        if (Config::get('keycloak-web.remember_users', false)) {
            $profile = $this->cache()->get($this->rememberKey($identifier));

            if (is_array($profile)) {
                return $this->retrieveByCredentials($profile);
            }
        }

        if (static::$userResolver) {
            $user = call_user_func(static::$userResolver, $identifier, $this);

            return is_array($user) ? $this->retrieveByCredentials($user) : ($user ?: null);
        }

        return null;
    }

    /**
     * Register a callback to retrieve users not remembered in cache.
     *
     * The callback receives the identifier and this provider and should return
     * a profile array (like Keycloak userinfo), an Authenticatable or null.
     *
     * @param  callable|null $callback
     * @return void
     */
    public static function resolveUsersUsing(?callable $callback)
    {
        static::$userResolver = $callback;
    }

    /**
     * Keep the user profile in cache, so retrieveById() can find it later.
     *
     * @param  Authenticatable $user
     * @param  array $profile Keycloak userinfo
     * @return void
     */
    public function rememberUser(Authenticatable $user, array $profile)
    {
        $identifier = $user->getAuthIdentifier();

        if (is_null($identifier) || $identifier === '' || ! Config::get('keycloak-web.remember_users', false)) {
            return;
        }

        $ttl = Config::get('keycloak-web.remember_users_ttl', 2592000);
        $ttl = ($ttl === null || $ttl === '') ? null : (int) $ttl;

        $this->cache()->put($this->rememberKey($identifier), $profile, $ttl);
    }

    /**
     * Remove a remembered user
     *
     * @param  mixed $identifier
     * @return void
     */
    public function forgetUser($identifier)
    {
        $this->cache()->forget($this->rememberKey($identifier));
    }

    /**
     * The cache key for a remembered user
     *
     * @param  mixed $identifier
     * @return string
     */
    protected function rememberKey($identifier)
    {
        return 'keycloak-web-user:' . $identifier;
    }

    /**
     * The cache store for remembered users
     *
     * @return \Illuminate\Contracts\Cache\Repository
     */
    protected function cache()
    {
        return Cache::store(Config::get('keycloak-web.remember_users_store'));
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param  mixed  $identifier
     * @param  string  $token
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByToken($identifier, $token)
    {
        throw new \BadMethodCallException('Unexpected method [retrieveByToken] call');
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  string  $token
     * @return void
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        throw new \BadMethodCallException('Unexpected method [updateRememberToken] call');
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array  $credentials
     * @return bool
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        throw new \BadMethodCallException('Unexpected method [validateCredentials] call');
    }

    /**
     * Rehash the user's password if required and supported.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array  $credentials
     * @param  bool  $force
     * @return void
     */
    public function rehashPasswordIfRequired(Authenticatable $user, array $credentials, bool $force = false)
    {
        throw new \BadMethodCallException('Unexpected method [rehashPasswordIfRequired] call');
    }
}
