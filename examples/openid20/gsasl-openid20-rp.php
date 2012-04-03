<?php # -*- mode: php -*-

// gsasl-openid20-rp.php --- OpenID RP for smtp-server-openid20.c.
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

$store_path = '/tmp/gsasl-openid20-store';
$store = new Auth_OpenID_FileStore($store_path);
$consumer = new Auth_OpenID_Consumer($store);

$matches = array();
if (preg_match (",^/([A-Za-z0-9]+)$,", $_SERVER['PATH_INFO'], $matches) == 1) {
  $nonce = $matches[1];
}

$return_to = file_get_contents ("$store_path/state/$nonce/return_to");

$response = $consumer->complete($return_to);

if ($response->status == Auth_OpenID_CANCEL) {

  file_put_contents ("$store_path/state/$nonce/fail",
		     "openid.error=cancel");

  print "OpenID authentication cancelled";

} else if ($response->status == Auth_OpenID_FAILURE) {

  file_put_contents ("$store_path/state/$nonce/fail",
		     "openid.error=failure");

  print "OpenID authentication failed: " . $response->message;

} else if ($response->status == Auth_OpenID_SUCCESS) {

  $claimed = $response->identity_url;

  $sreg_resp = Auth_OpenID_SRegResponse::fromSuccessResponse($response);
  $sreg = $sreg_resp->contents();
  $outcome = "";
  if (@$sreg['email']) {
    $outcome .= "&email=" . urlencode($sreg['email']);
  }
  if (@$sreg['nickname']) {
    $outcome .= "&nickname=" . urlencode($sreg['nickname']);
  }
  if (@$sreg['fullname']) {
    $outcome .= "&fullname=" . urlencode($sreg['fullname']);
  }
  $outcome = trim ($outcome, "&");

  file_put_contents ("$store_path/state/$nonce/sreg", $outcome);
  file_put_contents ("$store_path/state/$nonce/success", $claimed);

  print "Congratulations!  You are authenticated as: " . $claimed;
}

?>
