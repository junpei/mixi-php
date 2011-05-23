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
}
