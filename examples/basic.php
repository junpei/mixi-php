<?php

set_include_path('../');
require_once 'Mixi.php';

$consumerKey = 'consumerKey';
$consumerSecret = 'consumerSecret';

##
# authorize
#

# 1.
$mixi = new Mixi(array(
	'clientId' => $consumerKey
));
$mixi->authorize()->redirect();
# or
# header("Location: {$mixi->authorize()->getUrl()}");
# exit;

# 2.

$mixi = new Mixi();
$mixi->clientId = $consumerKey;
$mixi->authorize()->redirect();

# 3.

$mixi = new Mixi();
$mixi->authorize()->clientId($consumerKey)->redirect();

# 4.
$mixi = new Mixi();
$mixi->authorize()->clientId($consumerKey)->mobile()->redirect();

# 5.
$mixi = new Mixi();
$mixi->authorize()->clientId($consumerKey)->touch()->redirect();
# or
# $mixi->authorize()->clientId($consumerKey)->smartphone()->redirect();

# 6.
$mixi = new Mixi();
$mixi->authorize()->clientId($consumerKey)->display('touch')->redirect();

# 7.
$mixi = new Mixi(array(
	'clientId' => $consumerKey
));
$mixi->authorize()->scope('r_profile', 'r_updates')->redirect();
# or
# $mixi->authorize()->scope(array('r_profile', 'r_updates'))->redirect();

# 8.
$mixi = new Mixi(array(
	'clientId' => $consumerKey
));
$mixi->authorize()->responseType('authorization_code')->redirect();

# 9.
$mixi = new Mixi(array(
	'clientId' => $consumerKey
));
$mixi->authorize()->state(session_id())->redirect();
