<?php

namespace Uepg\KeycloakWebGuard\Services;

use Exception;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use Throwable;
use Uepg\KeycloakWebGuard\Auth\KeycloakAccessToken;
use Uepg\KeycloakWebGuard\Exceptions\KeycloakException;
use Uepg\KeycloakWebGuard\Exceptions\KeycloakRequestException;
use Uepg\KeycloakWebGuard\Exceptions\KeycloakTokenException;

class KeycloakService
{
    /**
     * The Session key for token
     */
    public const KEYCLOAK_SESSION = '_keycloak_token';

    /**
     * The Session key for state
     */
    public const KEYCLOAK_SESSION_STATE = '_keycloak_state';

    /**
     * The Session key for the cached user profile
     */
    public const KEYCLOAK_SESSION_PROFILE = '_keycloak_profile';

    /**
     * Keycloak URL
     *
     * @var string
     */
    protected $baseUrl;

    /**
     * Keycloak Realm
     *
     * @var string
     */
    protected $realm;

    /**
     * Keycloak Client ID
     *
     * @var string
     */
    protected $clientId;

    /**
     * Keycloak Client Secret
     *
     * @var string
     */
    protected $clientSecret;

    /**
     * Keycloak OpenId Configuration
     *
     * @var array
     */
    protected $openid;

    /**
     * Keycloak OpenId Cache Configuration
     *
     * @var array
     */
    protected $cacheOpenid;

    /**
     * Keycloak OpenId Cache TTL in seconds (null caches forever)
     *
     * @var int|null
     */
    protected $cacheOpenidTtl;

    /**
     * Verify the JWT signatures
     *
     * @var bool
     */
    protected $verifySignature;

    /**
     * Realm public key used to verify signatures (instead of the JWKS endpoint)
     *
     * @var string
     */
    protected $realmPublicKey;

    /**
     * Keep the user profile in session while the access token does not change
     *
     * @var bool
     */
    protected $cacheUserProfile;

    /**
     * CallbackUrl
     *
     * @var array
     */
    protected $callbackUrl;

    /**
     * RedirectLogout
     *
     * @var array
     */
    protected $redirectLogout;

    /**
     * The state for authorization request
     *
     * @var string
     */
    protected $state;

    /**
     * The HTTP Client
     *
     * @var ClientInterface
     */
    protected $httpClient;

    /**
     * @var array of strings
     */
    protected $scopes = ['openid'];

    /**
     * The Constructor
     * You can extend this service setting protected variables before call
     * parent constructor to comunicate with Keycloak smoothly.
     *
     * @param ClientInterface $client
     * @return void
     */
    public function __construct(ClientInterface $client)
    {
        if (is_null($this->baseUrl)) {
            $this->baseUrl = trim(Config::get('keycloak-web.base_url'), '/');
        }

        if (is_null($this->realm)) {
            $this->realm = Config::get('keycloak-web.realm');
        }

        if (is_null($this->clientId)) {
            $this->clientId = Config::get('keycloak-web.client_id');
        }

        if (is_null($this->clientSecret)) {
            $this->clientSecret = Config::get('keycloak-web.client_secret');
        }

        if (is_null($this->cacheOpenid)) {
            $this->cacheOpenid = Config::get('keycloak-web.cache_openid', false);
        }

        if (is_null($this->cacheOpenidTtl)) {
            $ttl = Config::get('keycloak-web.cache_openid_ttl', 86400);
            $this->cacheOpenidTtl = ($ttl === null || $ttl === '') ? null : (int) $ttl;
        }

        if (is_null($this->verifySignature)) {
            $this->verifySignature = (bool) Config::get('keycloak-web.verify_signature', true);
        }

        if (is_null($this->realmPublicKey)) {
            $this->realmPublicKey = Config::get('keycloak-web.realm_public_key');
        }

        if (is_null($this->cacheUserProfile)) {
            $this->cacheUserProfile = (bool) Config::get('keycloak-web.cache_user_profile', false);
        }

        if (is_null($this->callbackUrl)) {
            $this->callbackUrl = route('keycloak.callback');
        }

        if (is_null($this->redirectLogout)) {
            $this->redirectLogout = Config::get('keycloak-web.redirect_logout');
        }

        $this->scopes = array_values(array_unique(array_merge($this->scopes, (array) Config::get('keycloak-web.scopes', []))));

        $this->state = $this->generateRandomState();
        $this->httpClient = $client;
    }

    /**
     * Return the login URL
     *
     * @link https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
     *
     * @return string
     */
    public function getLoginUrl()
    {
        $url = $this->getOpenIdValue('authorization_endpoint');
        $params = [
            'scope' => implode(' ', $this->scopes),
            'response_type' => 'code',
            'client_id' => $this->getClientId(),
            'redirect_uri' => $this->callbackUrl,
            'state' => $this->getState(),
        ];

        return $this->buildUrl($url, $params);
    }

    /**
     * Return the logout URL
     *
     * @return string
     */
    public function getLogoutUrl()
    {
        $url = $this->getOpenIdValue('end_session_endpoint');

        if (empty($this->redirectLogout)) {
            $this->redirectLogout = url('/');
        }

        $params = [
            'client_id' => $this->getClientId()
        ];
        $token = $this->retrieveToken();
        if (! empty($token['id_token'])) {
            $params['post_logout_redirect_uri'] = $this->redirectLogout;
            $params['id_token_hint'] = $token['id_token'];
        }

        return $this->buildUrl($url, $params);
    }

    /**
     * Return the register URL
     *
     * @link https://stackoverflow.com/questions/51514437/keycloak-direct-user-link-registration
     *
     * @return string
     */
    public function getRegisterUrl()
    {
        $url = $this->getLoginUrl();
        return str_replace('/auth?', '/registrations?', $url);
    }
    /**
     * Get access token from Code
     *
     * @param  string $code
     * @return array
     */
    public function getAccessToken($code)
    {
        $url = $this->getOpenIdValue('token_endpoint');
        $params = [
            'code' => $code,
            'client_id' => $this->getClientId(),
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->callbackUrl,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return $token;
    }

    /**
     * Refresh access token
     *
     * @param  string $refreshToken
     * @return array
     */
    public function refreshAccessToken($credentials)
    {
        if (empty($credentials['refresh_token'])) {
            return [];
        }

        $url = $this->getOpenIdValue('token_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'grant_type' => 'refresh_token',
            'refresh_token' => $credentials['refresh_token'],
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return $token;
    }

    /**
     * Invalidate Refresh
     *
     * @param  string $refreshToken
     * @return bool
     */
    public function invalidateRefreshToken($refreshToken)
    {
        $url = $this->getOpenIdValue('end_session_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'refresh_token' => $refreshToken,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);
            return $response->getStatusCode() === 204;
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return false;
    }

    /**
     * Get access token from Code
     * @param  array $credentials
     * @return array
     */
    public function getUserProfile($credentials)
    {
        $credentials = $this->refreshTokenIfNeeded($credentials);

        $user = [];
        try {
            // Validate JWT Token
            $token = new KeycloakAccessToken($credentials);

            if (empty($token->getAccessToken())) {
                throw new KeycloakTokenException('Access Token is invalid.');
            }

            $claims = array(
                'aud' => $this->getClientId(),
                'iss' => $this->getOpenIdValue('issuer'),
            );

            $token->validateIdToken($claims);
            $this->verifyTokenSignatures($token);

            // Same access token as last request: reuse the profile
            $cached = $this->cacheUserProfile ? session()->get(self::KEYCLOAK_SESSION_PROFILE) : null;
            if (! empty($cached['user']) && hash_equals((string) ($cached['token'] ?? ''), $this->hashToken($token->getAccessToken()))) {
                return $cached['user'];
            }

            // Get userinfo
            $url = $this->getOpenIdValue('userinfo_endpoint');
            $headers = [
                'Authorization' => 'Bearer ' . $token->getAccessToken(),
                'Accept' => 'application/json',
            ];

            $response = $this->httpClient->request('GET', $url, ['headers' => $headers]);

            if ($response->getStatusCode() !== 200) {
                throw new KeycloakRequestException('Was not able to get userinfo (not 200)');
            }

            $user = $response->getBody()->getContents();
            $user = json_decode($user, true);

            if (! is_array($user)) {
                throw new KeycloakRequestException('Userinfo response is not valid JSON.');
            }

            // Validate retrieved user is owner of token
            if (! $token->validateSub($user['sub'] ?? '')) {
                throw new KeycloakTokenException('Userinfo "sub" does not match the ID Token.');
            }

            if ($this->cacheUserProfile) {
                session()->put(self::KEYCLOAK_SESSION_PROFILE, [
                    'token' => $this->hashToken($token->getAccessToken()),
                    'user' => $user,
                ]);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);
        } catch (Exception $e) {
            $user = [];
            $this->reportException($e);
        }

        return $user;
    }

    /**
     * Retrieve Token from Session
     *
     * @return array|null
     */
    public function retrieveToken()
    {
        return session()->get(self::KEYCLOAK_SESSION);
    }

    /**
     * Save Token to Session
     *
     * @return void
     */
    public function saveToken($credentials)
    {
        session()->put(self::KEYCLOAK_SESSION, $credentials);
        session()->save();
    }

    /**
     * Remove Token from Session
     *
     * @return void
     */
    public function forgetToken()
    {
        session()->forget([self::KEYCLOAK_SESSION, self::KEYCLOAK_SESSION_PROFILE, '_keycloak_remembered']);
        session()->save();
    }

    /**
     * Validate State from Session
     *
     * @return void
     */
    public function validateState($state)
    {
        $challenge = session()->get(self::KEYCLOAK_SESSION_STATE);
        return (! empty($state) && ! empty($challenge) && $challenge === $state);
    }

    /**
     * Save State to Session
     *
     * @return void
     */
    public function saveState()
    {
        session()->put(self::KEYCLOAK_SESSION_STATE, $this->state);
        session()->save();
    }

    /**
     * Remove State from Session
     *
     * @return void
     */
    public function forgetState()
    {
        session()->forget(self::KEYCLOAK_SESSION_STATE);
        session()->save();
    }

    /**
     * Build a URL with params
     *
     * @param  string $url
     * @param  array $params
     * @return string
     */
    public function buildUrl($url, $params)
    {
        $parsedUrl = parse_url($url);
        if (empty($parsedUrl['host'])) {
            return trim($url, '?') . '?' . http_build_query($params);
        }

        if (! empty($parsedUrl['port'])) {
            $parsedUrl['host'] .= ':' . $parsedUrl['port'];
        }

        $parsedUrl['scheme'] = (empty($parsedUrl['scheme'])) ? 'https' : $parsedUrl['scheme'];
        $parsedUrl['path'] = (empty($parsedUrl['path'])) ? '' : $parsedUrl['path'];

        $url = $parsedUrl['scheme'] . '://' . $parsedUrl['host'] . $parsedUrl['path'];
        $query = [];

        if (! empty($parsedUrl['query'])) {
            $parsedUrl['query'] = explode('&', $parsedUrl['query']);

            foreach ($parsedUrl['query'] as $value) {
                $value = explode('=', $value);

                if (count($value) < 2) {
                    continue;
                }

                $key = array_shift($value);
                $value = implode('=', $value);

                $query[$key] = urldecode($value);
            }
        }

        $query = array_merge($query, $params);

        return $url . '?' . http_build_query($query);
    }

    /**
     * Return the client id for requests
     *
     * @return string
     */
    protected function getClientId()
    {
        return $this->clientId;
    }

    /**
     * Return the state for requests
     *
     * @return string
     */
    protected function getState()
    {
        return $this->state;
    }

    /**
     * Return a value from the Open ID Configuration
     *
     * @param  string $key
     * @return string
     */
    protected function getOpenIdValue($key)
    {
        if (! $this->openid) {
            $this->openid = $this->getOpenIdConfiguration();
        }

        return Arr::get($this->openid, $key);
    }

    /**
     * Retrieve OpenId Endpoints
     *
     * @return array
     */
    protected function getOpenIdConfiguration()
    {
        $cacheKey = 'keycloak_web_guard_openid-' . $this->realm . '-' . md5($this->baseUrl);

        // From cache?
        if ($this->cacheOpenid) {
            $configuration = Cache::get($cacheKey, []);

            if (! empty($configuration)) {
                return $configuration;
            }
        }

        // Request if cache empty or not using
        $url = $this->baseUrl . '/realms/' . $this->realm;
        $url = $url . '/.well-known/openid-configuration';

        $configuration = [];

        try {
            $response = $this->httpClient->request('GET', $url);

            if ($response->getStatusCode() === 200) {
                $configuration = $response->getBody()->getContents();
                $configuration = json_decode($configuration, true) ?: [];
            }
        } catch (GuzzleException $e) {
            throw new KeycloakRequestException('[Keycloak Error] It was not possible to load OpenId configuration: ' . $e->getMessage(), 0, $e);
        }

        // Save cache
        if ($this->cacheOpenid && ! empty($configuration)) {
            Cache::put($cacheKey, $configuration, $this->cacheOpenidTtl);
        }

        return $configuration;
    }

    /**
     * Verify the signature of the access and ID tokens
     *
     * @param  KeycloakAccessToken $token
     * @throws KeycloakTokenException
     * @return void
     */
    protected function verifyTokenSignatures(KeycloakAccessToken $token)
    {
        if (! $this->verifySignature) {
            return;
        }

        foreach ([$token->getAccessToken(), $token->getIdToken()] as $jwt) {
            if (empty($jwt)) {
                continue;
            }

            try {
                $this->decodeJwt($jwt, $this->getSigningKeys());
            } catch (\UnexpectedValueException $e) {
                // Unknown "kid": keys may have been rotated, so try again without cache
                if (! empty($this->realmPublicKey) || strpos($e->getMessage(), '"kid"') === false) {
                    throw new KeycloakTokenException('Token signature is invalid: ' . $e->getMessage(), 0, $e);
                }

                try {
                    $this->decodeJwt($jwt, $this->getSigningKeys(true));
                } catch (Exception $e) {
                    throw new KeycloakTokenException('Token signature is invalid: ' . $e->getMessage(), 0, $e);
                }
            } catch (KeycloakException $e) {
                throw $e;
            } catch (Exception $e) {
                throw new KeycloakTokenException('Token signature is invalid: ' . $e->getMessage(), 0, $e);
            }
        }
    }

    /**
     * Decode a JWT checking its signature
     *
     * Time based claims are validated by KeycloakAccessToken, so we allow
     * a small leeway here to avoid failing for clock drift.
     *
     * @param  string $jwt
     * @param  Key|array $keys
     * @return void
     */
    protected function decodeJwt($jwt, $keys)
    {
        $leeway = JWT::$leeway;
        JWT::$leeway = max($leeway, 60);

        try {
            JWT::decode($jwt, $keys);
        } finally {
            JWT::$leeway = $leeway;
        }
    }

    /**
     * Get the keys used to verify the token signatures
     *
     * Uses "realm_public_key" when configured, otherwise the realm JWKS.
     *
     * @param  bool $fresh Ignore cache
     * @throws KeycloakException
     * @return Key|Key[]
     */
    protected function getSigningKeys($fresh = false)
    {
        if (! empty($this->realmPublicKey)) {
            $key = trim($this->realmPublicKey);

            if (strpos($key, '-----BEGIN') === false) {
                $key = "-----BEGIN PUBLIC KEY-----\n" . wordwrap($key, 64, "\n", true) . "\n-----END PUBLIC KEY-----";
            }

            return new Key($key, 'RS256');
        }

        $cacheKey = 'keycloak_web_guard_jwks-' . $this->realm . '-' . md5($this->baseUrl);

        $jwks = ($this->cacheOpenid && ! $fresh) ? Cache::get($cacheKey, []) : [];

        if (empty($jwks)) {
            $url = $this->getOpenIdValue('jwks_uri');
            if (empty($url)) {
                throw new KeycloakException('[Keycloak Error] OpenId configuration has no "jwks_uri".');
            }

            try {
                $response = $this->httpClient->request('GET', $url);
                $jwks = json_decode($response->getBody()->getContents(), true) ?: [];
            } catch (GuzzleException $e) {
                throw new KeycloakRequestException('[Keycloak Error] It was not possible to load the realm keys: ' . $e->getMessage(), 0, $e);
            }

            // Only signature keys
            $jwks['keys'] = array_values(array_filter($jwks['keys'] ?? [], function ($key) {
                return ($key['use'] ?? 'sig') === 'sig';
            }));

            if (empty($jwks['keys'])) {
                throw new KeycloakException('[Keycloak Error] The realm has no signature keys.');
            }

            if ($this->cacheOpenid) {
                Cache::put($cacheKey, $jwks, $this->cacheOpenidTtl);
            }
        }

        return JWK::parseKeySet($jwks, 'RS256');
    }

    /**
     * Hash a token to be stored in session
     *
     * @param  string $token
     * @return string
     */
    protected function hashToken($token)
    {
        return hash('sha256', (string) $token);
    }

    /**
     * Check we need to refresh token and refresh if needed
     *
     * @param  array $credentials
     * @return array
     */
    protected function refreshTokenIfNeeded($credentials)
    {
        if (! is_array($credentials) || empty($credentials['access_token']) || empty($credentials['refresh_token'])) {
            return $credentials;
        }

        $token = new KeycloakAccessToken($credentials);
        if (! $token->hasExpired()) {
            return $credentials;
        }

        $credentials = $this->refreshAccessToken($credentials);

        if (empty($credentials['access_token'])) {
            $this->forgetToken();
            return [];
        }

        $this->saveToken($credentials);
        return $credentials;
    }

    /**
     * Report a GuzzleException
     *
     * @param  GuzzleException $e
     * @return void
     */
    protected function logException(GuzzleException $e)
    {
        $this->reportException(KeycloakRequestException::fromGuzzle($e));
    }

    /**
     * Send an exception to Laravel's exception handler, so the app decides
     * whether and how it is logged (dontReport, level, reportable...).
     *
     * @param  Throwable $e
     * @return void
     */
    protected function reportException(Throwable $e)
    {
        if ($e instanceof GuzzleException) {
            $e = KeycloakRequestException::fromGuzzle($e);
        } elseif (! $e instanceof KeycloakException) {
            $e = new KeycloakException('[Keycloak Service] ' . $e->getMessage(), 0, $e);
        }

        report($e);
    }

    /**
     * Return a random state parameter for authorization
     *
     * @return string
     */
    protected function generateRandomState()
    {
        return bin2hex(random_bytes(16));
    }
}
