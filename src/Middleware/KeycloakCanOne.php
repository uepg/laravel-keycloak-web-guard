<?php

namespace Uepg\KeycloakWebGuard\Middleware;

use Closure;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\Auth;

class KeycloakCanOne extends KeycloakAuthenticated
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string  ...$guards Roles separated by "|" (one is enough)
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
        foreach ($guards as $guard) {
            if (Auth::hasRole($guard)) {
                return $next($request);
            }
        }

        throw new AuthorizationException('Forbidden', 403);
    }
}
