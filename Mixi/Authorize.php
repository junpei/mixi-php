<?php

class Mixi_Authorize
{
    protected $uri = null;

    private $_pc = 'https://mixi.jp/connect_authorize.pl';
    private $_mobile = 'http://m.mixi.jp/connect_authorize.pl';

    protected $client_id = null;
    protected $response_type = 'code';
    protected $scope = 'r_profile';
    # r_profile r_updates [rw]_voice w_share [rw]_photo [rw]_message w_diary
    protected $display = 'pc';
    # pc touch|smartphone
    protected $state = null;

    public function __construct($options = array())
    {
        $this->uri = $this->_pc;

        foreach ($options as $key => $value) {
            if (isset($value)) {
                $this->$key = $value;
            }
        }
    }
    public function __set($key, $value)
    {
        if (property_exists($this, $key)) {
            $this->$key = $value;
        }

        else {
            require_once 'Exception.php';
            throw new Mixi_Exception('property not exists.');
        }

        return $this;
    }
    public function __call($name, $args) {
        if (property_exists($this, $name)) {
            $this->$name = $args[0];
        }

        else {
            require_once 'Exception.php';
            throw new Mixi_Exception('property not exists.');
        }

        return $this;
    }

    public function pc()
    {
        $this->uri = $this->_pc;
        $this->display = 'pc';
        return $this;
    }
    public function touch()
    {
        $this->uri = $this->_pc;
        $this->display = 'touch';
        return $this;
    }
    public function smartphone()
    {
        $this->uri = $this->_pc;
        $this->display = 'smartphone';
        return $this;
    }
    public function mobile()
    {
        $this->uri = $this->_mobile;
        return $this;
    }
    public function scope($value)
    {
        if (func_num_args() > 1) {
            $this->scope = join(' ', func_get_args());
        }

        else if (is_array($value)) {
            $this->scope = join(' ', $value);
        }

        else if (is_string($value)) {
            $this->scope = $value;
        }

        else {
            require_once 'Exception.php';
            throw new Mixi_Exception('scope invalid.');
        }

        return $this;
    }
    public function getUrl()
    {
        $queries = array(
            'client_id'     => $this->client_id,
            'response_type' => $this->response_type,
            'scope'         => $this->scope,
            'display'       => $this->display
        );

        if (isset($this->state)) {
            $queries['state'] = $this->state;
        }

        return $this->uri . '?' . http_build_query($queries);
    }
    public function redirect()
    {
        header("Location: {$this->getUrl()}\n");
        exit;
    }
}
