<?php

return [
    /**
     * Keycloak Url
     *
     * Generally https://your-server.com/auth
     */
    'base_url' => env('KEYCLOAK_BASE_URL', ''),

    /**
     * Keycloak Realm
     *
     * Default is master
     */
    'realm' => env('KEYCLOAK_REALM', 'master'),

    /**
     * Verify the signature of the access and ID tokens.
     *
     * Keys are loaded from the realm JWKS endpoint ("jwks_uri" from OpenId configuration).
     */
    'verify_signature' => env('KEYCLOAK_VERIFY_SIGNATURE', true),

    /**
     * The Keycloak Server realm public key (string). Optional.
     *
     * If set, it's used to verify signatures (RS256) instead of the JWKS endpoint.
     * Remember to update it when you rotate the realm keys.
     *
     * @see Keycloak >> Realm Settings >> Keys >> RS256 >> Public Key
     */
    'realm_public_key' => env('KEYCLOAK_REALM_PUBLIC_KEY', null),

    /**
     * Keycloak Client ID
     *
     * @see Keycloak >> Clients >> Installation
     */
    'client_id' => env('KEYCLOAK_CLIENT_ID', null),

    /**
     * Keycloak Client Secret
     *
     * @see Keycloak >> Clients >> Installation
     */
    'client_secret' => env('KEYCLOAK_CLIENT_SECRET', null),

    /**
     * We can cache the OpenId Configuration
     * The result from /realms/{realm-name}/.well-known/openid-configuration
     *
     * @link https://www.keycloak.org/docs/3.2/securing_apps/topics/oidc/oidc-generic.html
     */
    'cache_openid' => env('KEYCLOAK_CACHE_OPENID', false),

    /**
     * How long (in seconds) to cache the OpenId Configuration and realm keys.
     * Use null to cache forever.
     */
    'cache_openid_ttl' => env('KEYCLOAK_CACHE_OPENID_TTL', 86400),

    /**
     * Keep the user profile (userinfo) in session until the access token changes,
     * avoiding a request to Keycloak on every page load.
     *
     * The token is still validated on every request.
     */
    'cache_user_profile' => env('KEYCLOAK_CACHE_USER_PROFILE', false),

    /**
     * Remember users profile in cache after login, so the user provider can
     * find them by id (retrieveById). Useful for packages that show users
     * who are not logged in, like Laravel Pulse.
     *
     * Profiles (name, email...) stay in cache for "remember_users_ttl" seconds.
     * "remember_users_store" is the cache store (null is the default store).
     */
    'remember_users' => env('KEYCLOAK_REMEMBER_USERS', false),

    'remember_users_ttl' => env('KEYCLOAK_REMEMBER_USERS_TTL', 2592000),

    'remember_users_store' => env('KEYCLOAK_REMEMBER_USERS_STORE', null),

    /**
     * Page to redirect after callback if there's no "intent"
     *
     * @see Uepg\KeycloakWebGuard\Controllers\AuthController::callback()
     */
    'redirect_url' => env('KEYCLOAK_REDIRECT_URL', '/admin'),

    /**
     * Page to redirect after logout on Keycloak
     *
     * Default (null) is the app home: url('/')
     */
    'redirect_logout' => env('KEYCLOAK_REDIRECT_LOGOUT', null),

    /**
     * The routes for authenticate
     *
     * Accept a string as the first parameter of route() or false to disable the route.
     *
     * The routes will receive the name "keycloak.{route}" and login/callback are required.
     * So, if you make it false, you should register a named 'keycloak.login' route and extend
     * the Uepg\KeycloakWebGuard\Controllers\AuthController controller.
     */
    'routes' => [
        'login' => 'login',
        'logout' => 'logout',
        'register' => 'register',
        'callback' => 'callback',
    ],

    /**
     * HTTP methods accepted by the logout route.
     *
     * We recommend ['POST'] (protected by CSRF), using a form to logout.
     * Default is ['GET'] for backwards compatibility.
     */
    'logout_methods' => ['GET'],

    /**
     * GuzzleHttp Client options
     *
     * @link http://docs.guzzlephp.org/en/stable/request-options.html
     */
    'guzzle_options' => [],

    /**
     * Keycloak optional scopes
     *
     * array of strings
     */
    'scopes' => [],
];
