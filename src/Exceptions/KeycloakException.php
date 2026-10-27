<?php

namespace Uepg\KeycloakWebGuard\Exceptions;

/**
 * Base exception for every error raised by this package.
 *
 * Errors are sent to Laravel's exception handler (through report()), so you
 * can silence or reroute them in your app, for example:
 *
 *     $exceptions->dontReport(KeycloakException::class);
 */
class KeycloakException extends \RuntimeException
{
}
