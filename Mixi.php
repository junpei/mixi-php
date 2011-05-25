<?php

require_once 'OAuth2/OAuth2Client.php';
require_once 'Mixi/Authorize.php';

class Mixi extends OAuth2\OAuth2Client
{
    private $_authorize = null;

    public function __construct()
    {
        forward_static_call_array(array('parent', '__construct'), func_get_args());

        $this->_authorize = new Mixi_Authorize(array(
            'client_id' => $this->getVariable('client_id'),
            'response_type' => $this->getVariable('response_type'),
            'scope' => $this->getVariable('scope'),
            'display' => $this->getVariable('display'),
            'state' => $this->getVariable('state')
        ));
    }
    public function authorize()
    {
        return $this->_authorize;
    }
    public function getRequestUri()
    {
        $requestUri = parent::getRequestUri();

        if (preg_match('/^([^?]+)/', $requestUri, $matches)) {
            return $matches[0];
        }

        return $requestUri;
    }
    public function getSession()
    {
        if ($session = parent::getSession()) {
            return $session;
        }

        else if ($refreshToken = $this->getVariable('refresh_token')) {
            $accessToken = $this->getAccessTokenFromRefreshToken($refreshToken);

            if ($accessToken && isset($accessToken['expires_in'])) {
                $this->setVariable('expires', time() + $accessToken['expires_in']);
            }

            $session = $this->getSessionObject($accessToken);
            $session = $this->validateSessionObject($session);
            $this->setSession($session);

            return $session;
        }

        return null;
    }
    /**
     * TODO: expiresのtypoが修正されたらこのメソッドは必要なし
     */
    protected function getSessionObject($access_token = NULL)
    {
        $session = NULL;

        // Try generate local version of session cookie.
        if (!empty($access_token) && isset($access_token['access_token'])) {
            $session['access_token'] = $access_token['access_token'];
            $session['base_domain'] = $this->getVariable('base_domain', OAUTH2_DEFAULT_BASE_DOMAIN);
            $session['expires'] = isset($access_token['expires_in']) ? time() + $access_token['expires_in'] : time() + $this->getVariable('expires_in', OAUTH2_DEFAULT_EXPIRES_IN);
            $session['refresh_token'] = isset($access_token['refresh_token']) ? $access_token['refresh_token'] : '';
            $session['scope'] = isset($access_token['scope']) ? $access_token['scope'] : '';
            $session['secret'] = md5(base64_encode(pack('N6', mt_rand(), mt_rand(), mt_rand(), mt_rand(), mt_rand(), uniqid())));

            // Provide our own signature.
            $sig = self::generateSignature(
                $session,
                $this->getVariable('client_secret')
            );
            $session['sig'] = $sig;
        }

        // Try loading session from $_REQUEST.
        if (!$session && isset($_REQUEST['session'])) {
            $session = json_decode(
                get_magic_quotes_gpc()
                    ? stripslashes($_REQUEST['session'])
                    : $_REQUEST['session'],
                TRUE
            );
        }

        return $session;
    }
    private function getAccessTokenFromRefreshToken($refreshToken)
    {
        if ($this->getVariable('access_token_uri') &&
            $this->getVariable('client_id') &&
            $this->getVariable('client_secret')
        ) {
            return json_decode($this->makeRequest(
                $this->getVariable('access_token_uri'),
                'POST',
                array(
                    'grant_type' => 'refresh_token',
                    'client_id' => $this->getVariable('client_id'),
                    'client_secret' => $this->getVariable('client_secret'),
                    'refresh_token' => $refreshToken
                )
            ), TRUE);
        }

        return null;
    }
}
