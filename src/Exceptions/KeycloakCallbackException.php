<?php

namespace Uepg\KeycloakWebGuard\Exceptions;

class KeycloakCallbackException extends KeycloakException
{
    /**
     * Keycloak Callback Error
     *
     * @param string $error
     */
    public function __construct(string $error = '')
    {
        $message = '[Keycloak Error] ' . $error;

        parent::__construct($message);
    }
}
