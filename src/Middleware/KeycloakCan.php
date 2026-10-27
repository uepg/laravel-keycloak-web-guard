<?php

namespace Uepg\KeycloakWebGuard\Middleware;

use Closure;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\Auth;

class KeycloakCan extends KeycloakAuthenticated
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string  ...$guards Roles separated by "|" (all are required)
     * @return mixed
     */
    public function handle($request, Closure $next, ...$guards)
    {
        if (! Auth::check()) {
            $this->unauthenticated($request, []);
        }

        if (empty($guards)) {
            return $next($request);
        }

        $guards = explode('|', ($guards[0] ?? ''));
        if (Auth::hasRole($guards)) {
            return $next($request);
        }

        throw new AuthorizationException('Forbidden', 403);
    }
}
