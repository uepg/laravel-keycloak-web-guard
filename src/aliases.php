<?php

/**
 * Backwards compatibility with the "vizir/laravel-keycloak-web-guard" package.
 *
 * Classes moved from Vizir\KeycloakWebGuard to Uepg\KeycloakWebGuard on 5.0.
 * Old names are aliases of the new classes, so configs, subclasses, catch
 * blocks and dontReport() using Vizir\... keep working.
 *
 * The aliases are registered eagerly: "catch" and "instanceof" don't trigger
 * the autoloader, so a lazy alias would silently not match.
 *
 * @deprecated 5.0 Use Uepg\KeycloakWebGuard. These aliases will be removed on 6.0.
 */
foreach ([
    'Auth\\Guard\\KeycloakWebGuard',
    'Auth\\KeycloakAccessToken',
    'Auth\\KeycloakWebUserProvider',
    'Controllers\\AuthController',
    'Exceptions\\KeycloakCallbackException',
    'Exceptions\\KeycloakCanException',
    'Exceptions\\KeycloakException',
    'Exceptions\\KeycloakRequestException',
    'Exceptions\\KeycloakTokenException',
    'Facades\\KeycloakWeb',
    'KeycloakWebGuardServiceProvider',
    'Middleware\\KeycloakAuthenticated',
    'Middleware\\KeycloakCan',
    'Middleware\\KeycloakCanOne',
    'Models\\KeycloakUser',
    'Services\\KeycloakService',
] as $class) {
    if (! class_exists('Vizir\\KeycloakWebGuard\\' . $class, false)) {
        class_alias('Uepg\\KeycloakWebGuard\\' . $class, 'Vizir\\KeycloakWebGuard\\' . $class);
    }
}
