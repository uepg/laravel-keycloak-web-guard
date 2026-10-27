<?php

namespace Uepg\KeycloakWebGuard\Exceptions;

use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Str;

/**
 * A request to the Keycloak server failed.
 */
class KeycloakRequestException extends KeycloakException
{
    /**
     * Extra data to be logged by Laravel's exception handler
     *
     * @var array
     */
    protected $context = [];

    /**
     * Wrap a GuzzleException
     *
     * Only the method, URL (without query string), status code and a short
     * excerpt of the response body are kept: request headers are never logged
     * because they may carry tokens.
     *
     * @param  GuzzleException $e
     * @return static
     */
    public static function fromGuzzle(GuzzleException $e)
    {
        $context = [];

        if (method_exists($e, 'getRequest') && $e->getRequest()) {
            $context['method'] = $e->getRequest()->getMethod();
            $context['url'] = (string) $e->getRequest()->getUri()->withQuery('');
        }

        $response = method_exists($e, 'getResponse') ? $e->getResponse() : null;
        if ($response) {
            $context['status'] = $response->getStatusCode();
            $context['response'] = Str::limit((string) $response->getBody(), 500);
        }

        $exception = new static('[Keycloak Service] ' . $e->getMessage(), 0, $e);
        $exception->context = $context;

        return $exception;
    }

    /**
     * Get the exception's context information.
     *
     * @return array
     */
    public function context()
    {
        return $this->context;
    }
}
