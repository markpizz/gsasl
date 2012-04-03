#!/usr/bin/php5
<?php # -*- mode: php -*-

// gsasl-openid20-redirect.php --- OpenID redirector helper.
// Copyright (C) 2012 Simon Josefsson
//
// This file is part of GNU SASL.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

require_once "Auth/OpenID/Consumer.php";
require_once "Auth/OpenID/FileStore.php";
require_once "Auth/OpenID/SReg.php";
session_start ();

$store_path = $argv[1];
$nonce = $argv[2];
$openid_url = file_get_contents ($store_path . "/state/$nonce/openid_url");
$realm = file_get_contents ($store_path . "/state/$nonce/realm");
$return_to = file_get_contents ($store_path . "/state/$nonce/return_to");

print "nonce: ". $nonce ."\n";
print "openid_url: ". $openid_url ."\n";
print "realm: ". $realm ."\n";
print "return_to: ". $return_to ."\n";

$store = new Auth_OpenID_FileStore($store_path);
if (!$store) {
  print "error: Auth_OpenID_FileStore.\n";
  exit (1);
}

$consumer = new Auth_OpenID_Consumer($store);
if (!$consumer) {
  print "error: Auth_OpenID_Consumer.\n";
  exit (1);
}

$request = $consumer->begin($openid_url);
if (!$request) {
  print "error: Auth_OpenID_Consumer->begin.\n";
  exit (1);
}

$sreg = Auth_OpenID_SRegRequest::build(array(),
				array('nickname', 'fullname', 'email'));
if (!$sreg) {
  print "error: Auth_OpenID_SRegRequest::build\n";
  exit (1);
}

$request->addExtension($sreg);

$redirect_url = $request->redirectURL($realm, $return_to);
if (Auth_OpenID::isFailure($redirect_url)) {
  print ("error: Auth_OpenID_Consumer->redirectURL: " . $redirect_url->message);
  exit (1);
}

file_put_contents ($store_path . "/state/$nonce/redirect_url", $redirect_url);

print "redirect_url: ". $redirect_url ."\n";

?>
