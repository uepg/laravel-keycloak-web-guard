# CHANGELOG

All notable changes to this project will be documented in this file.

## 5.X - uepg/laravel-keycloak-web-guard

### [5.0.0] - Unreleased

Package renamed to `uepg/laravel-keycloak-web-guard` (it `replace`s `vizir/laravel-keycloak-web-guard`).

**Breaking**

* Namespace changed from `Vizir\KeycloakWebGuard` to `Uepg\KeycloakWebGuard`. The old names are kept as deprecated aliases until 6.0.
* Requires PHP 8.2+ and Laravel 11, 12 or 13.
* Token signatures are verified by default using the realm JWKS (`KEYCLOAK_VERIFY_SIGNATURE=false` disables it). `KEYCLOAK_REALM_PUBLIC_KEY`, if set, is now used for this.
* Errors are sent to Laravel's exception handler as `KeycloakException` subclasses instead of `Log::error()`, so apps can ignore them with `dontReport()` or change their level. Request headers (which carry tokens) are no longer dumped to the log.
* The user is rejected when userinfo `sub` doesn't match the ID token (the check existed but its result was ignored).
* With `app.debug` on, an invalid session now redirects to login instead of throwing `KeycloakCallbackException`.
* `KeycloakWebGuard::roles()` returns `[]` (not `false`) for guests.

**Fixed**

* `Auth::id()`, `$user->id` and `getAuthIdentifier()` were always `null`.
* `keycloak-web-can` / `keycloak-web-can-one` threw a `TypeError` for guests; they now redirect to login.
* `Logout` event received a `null` user.
* `Authenticated` event used the default guard name instead of the Keycloak guard name.
* Infinite loop when reporting an error while authenticating (Laravel's handler calls `Auth::id()`).
* Malformed tokens raised warnings; base64url padding.
* Guard, routes and middleware are registered on `boot()`, routes respect `route:cache`, and the service is scoped per request.

**Added**

* `keycloak-web-can-any` middleware alias (same as `keycloak-web-can-one`, which is kept).
* `remember_users` configs and `KeycloakWebUserProvider::resolveUsersUsing()`: `retrieveById()` can find users after login (for Laravel Pulse and similar). It returns `null` instead of throwing `BadMethodCallException`.
* `logout_methods` config (use `['POST']` to protect logout with CSRF).
* `cache_openid_ttl` (default 1 day) and `cache_user_profile` configs.
* `sub` and `preferred_username` are kept on `KeycloakUser`.
* Test suite and GitHub Actions CI.

## 4.X - Laravel 11

### [4.1.0] - 2024-08-05

* Added realm roles (props: @serumk)

### [4.0.1] - 2024-05-02

* Update KeycloakUser to Laravel 11 (props: @a-andrianova-variti)

### [4.0.0] - 2024-04-30

* Added another scopes to config (props: @Murielle666)
* Added Authenticated/Logout events (props: @neemiasjr)
* Removing deprecation warnings/future errors (props: @jesperbeisner)
* Update KeycloakWebUserProvider to Laravel 11 (props: @hydrokat)

## 3.X - Keycloak 18

### [3.0.1] - 2022-09-28

* Fix #79 (looping on KeycloakCan error). (props: @andrex47)

### [3.0.0] - 2022-09-23

* Support to Keycloak >= 18. (props: @serumk)

## 2.X - ROLES + Laravel 9

### [2.3.3] - 2022-03-20

* Support to Laravel 9.0. (props: @alvarofelipems)
* Allow access list roles in the Guard. (props: @socieboy)
* A typo in docs. (props: @atyakresna)

### [2.3.2] - 2021-01-27

* Support to Guzzle 7.

### [2.3.1] - 2021-01-27

* Fixed a problem in the expired check. (props: @gorkagv)

### [2.3.0] - 2020-10-30

* Support to Laravel 8.0. (props: @matthewhall-ca)
* Support to Laravel Gate.

### [2.2.0] - 2020-09-13

* Implementing more auth checks. (props for code review: @cyrillbolliger)
* Support to Laravel Gate.

### [2.1.1] - 2020-09-01

* Implementing state check on authorization flow. (props for code review: @cyrillbolliger)

Cyrill Bolliger alerted us today we were not using 'state' param on authentication request.
He did a responsible disclosure to sending a e-mail and we are very grateful (I hope pay him a beer/coffee someday).

### [2.1.0] - 2020-08-26

* ClientID as method to allow override

### [2.0.0] - 2020-06-01

* OpenID configuration refactored.

We'll request only if necessary.
It's a breaking change if you extend **Services/KeycloakService.php**.

Props: @matthewhall-ca

## 1.X - FIRST VERSION

### [1.X.X] - 2020-06-05

(We start CHANGELOG on 2.0.0)

* Configurations
* Auth based on Laravel
* Check of a role from Keycloak user profile
* Middleware for route access based on role
* Guzzle client options

### [1.0.0] - 2019-06-05

It's alive!

