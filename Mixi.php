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
     * mixiのPOSTはapplication/jsonなので。。
     */
    public function api($path, $method = 'GET', $params = array())
    {
        if (is_array($method) && empty($params)) {
            $params = $method;
            $method = 'GET';
        }

        if ($method !== 'GET' && $params) {
            self::$CURL_OPTS[CURLOPT_HTTPHEADER][] = 'Content-Type: application/json';
            self::$CURL_OPTS[CURLOPT_POSTFIELDS] = json_encode($params);
        }

        $result = json_decode($this->makeOAuth2Request(
            $this->getUri($path),
            $method,
            $params
        ), TRUE);

        // Results are returned, errors are thrown.
        if (is_array($result) && isset($result['error'])) {
            $e = new OAuth2Exception($result);
            switch ($e->getType()) {
                // OAuth 2.0 Draft 10 style.
            case 'invalid_token':
                $this->setSession(NULL);
            default:
                $this->setSession(NULL);
            }
            throw $e;
        }
        return $result;
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
            $session['base_domain'] = $this->getVariable(
                'base_domain', OAUTH2_DEFAULT_BASE_DOMAIN);
            $session['expires'] = isset($access_token['expires_in']) ?
                time() + $access_token['expires_in'] :
                time() + $this->getVariable('expires_in', OAUTH2_DEFAULT_EXPIRES_IN);
            $session['refresh_token'] = isset($access_token['refresh_token']) ?
                $access_token['refresh_token'] : '';
            $session['scope'] = isset($access_token['scope']) ?
                $access_token['scope'] : '';
            $session['secret'] = md5(
                base64_encode(
                    pack(
                        'N6', mt_rand(), mt_rand(),
                        mt_rand(), mt_rand(), mt_rand(), uniqid())));

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
    /**
     * query_stringにoauth_tokenを渡すのではなくAuthorizationヘッダに変更
     */
    protected function makeOAuth2Request($path, $method = 'GET', $params = array())
    {
        if (isset($params['oauth_token'])) {
            $oauthToken = $params['oauth_token'];
            unset($params['oauth_token']);
        }

        else {
            $oauthToken = $this->getAccessToken();
        }

        if (isset(self::$CURL_OPTS[CURLOPT_HTTPHEADER]) &&
            is_array(self::$CURL_OPTS[CURLOPT_HTTPHEADER])
        ) {
            self::$CURL_OPTS[CURLOPT_HTTPHEADER][] =
                'Authorization: OAuth ' . $oauthToken;
        }

        return $this->makeRequest($path, $method, $params);
    }
    /**
     * CURLOPT_POSTFIELDSの扱い方を変更
     */
    protected function makeRequest($path, $method = 'GET', $params = array())
    {
        $ch = curl_init();
        $opts = self::$CURL_OPTS;

        if ($params) {
            switch ($method) {
            case 'GET':
                $path .= '?' . http_build_query($params, NULL, '&');
                break;
                // Method override as we always do a POST.
            default:
                if ($this->getVariable('file_upload_support')) {
                    $opts[CURLOPT_POSTFIELDS] = $params;
                }
                else if (empty($opts[CURLOPT_POSTFIELDS])) {
                    $opts[CURLOPT_POSTFIELDS] = http_build_query($params, NULL, '&');
                }
            }
        }
        $opts[CURLOPT_URL] = $path;
        #if ($method === 'POST')
        #    throw new Zend_Exception(print_r($opts, true));

        // Disable the 'Expect: 100-continue' behaviour. This causes CURL to wait
        // for 2 seconds if the server does not support this header.
        if (isset($opts[CURLOPT_HTTPHEADER])) {
            $existing_headers = $opts[CURLOPT_HTTPHEADER];
            $existing_headers[] = 'Expect:';
            $opts[CURLOPT_HTTPHEADER] = $existing_headers;
        }
        else {
            $opts[CURLOPT_HTTPHEADER] = array('Expect:');
        }

        curl_setopt_array($ch, $opts);
        $result = curl_exec($ch);
        #if ($method === 'POST')
        #    throw new Zend_Exception(print_r($result, true));

        if (curl_errno($ch) == 60) { // CURLE_SSL_CACERT
            error_log('Invalid or no certificate authority found, using bundled information');
            curl_setopt($ch, CURLOPT_CAINFO,
                dirname(__FILE__) . '/fb_ca_chain_bundle.crt');
            $result = curl_exec($ch);
        }

        if ($result === FALSE) {
            $e = new OAuth2Exception(array(
                'code' => curl_errno($ch),
                'message' => curl_error($ch),
            ));
            curl_close($ch);
            throw $e;
        }
        curl_close($ch);

        // Split the HTTP response into header and body.
        list($headers, $body) = explode("\r\n\r\n", $result);
        $headers = explode("\r\n", $headers);

        // We catch HTTP/1.1 4xx or HTTP/1.1 5xx error response.
        if (strpos($headers[0], 'HTTP/1.1 4') !== FALSE || strpos($headers[0], 'HTTP/1.1 5') !== FALSE) {
            $result = array(
                'code' => 0,
                'message' => '',
            );

            if (preg_match('/^HTTP\/1.1 ([0-9]{3,3}) (.*)$/', $headers[0], $matches)) {
                $result['code'] = $matches[1];
                $result['message'] = $matches[2];
            }

            // In case retrun with WWW-Authenticate replace the description.
            foreach ($headers as $header) {
                if (preg_match("/^WWW-Authenticate:.*error='(.*)'/", $header, $matches)) {
                    $result['error'] = $matches[1];
                }
            }

            return json_encode($result);
        }

        return $body;
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
