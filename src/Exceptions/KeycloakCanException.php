<?php

namespace Uepg\KeycloakWebGuard\Exceptions;

use Illuminate\Auth\AuthenticationException;

/**
 * Kept for backwards compatibility. It is not thrown by the package:
 * the role middlewares throw an AuthorizationException.
 */
class KeycloakCanException extends AuthenticationException
{
}
