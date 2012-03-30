<?php # -*- mode: php -*-

// gsasl-saml20-sp.php --- SAML SP for smtp-server-saml20.c.
// Copyright (C) 2012  Simon Josefsson
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

require "lasso.php";

include "gsasl-saml20-config.php";

if (!isset($state_path) || !isset($cfg_path) || !is_writable($state_path)) {
  print "Error: Configuration error";
  exit (0);
}

if (!isset($_POST["SAMLResponse"])) {
  print "Error: Expected SAMLResponse POST data";
  exit (0);
}

$xml = base64_decode($_POST["SAMLResponse"]);
if (preg_match ("/<[^> ]+:Response[^>]+InResponseTo=\"([A-Za-z0-9_]+)\"/",
		$xml, $matches) != 1) {
  print "Error: Could not parse XML";
  error_log ("parsing XML failed: $xml");
  exit (0);
}
$id = $matches[1];
if (!file_exists ("$state_path/$id") && !mkdir ("$state_path/$id", 0770)) {
  error_log ("mkdir: $state_path/$id");
  exit (0);
}
file_put_contents ("$state_path/$id/post", $xml);
error_log ("saved SAMLResponse into $state_path/$id/post");

function error($msg) {
  global $state_path, $id;
  file_put_contents ("$state_path/$id/fail", "");
  print "Error: " . htmlentities($msg);
  exit(0);
}

try {
  $server = new LassoServer("$cfg_path/sp-metadata.xml",
			    "$cfg_path/sp-key.pem", "",
			    "$cfg_path/sp-crt.pem");
  $idps = "";
  foreach (glob("$cfg_path/*", GLOB_ONLYDIR) as $dir) {
    if (is_readable ("$dir/idp-metadata.xml")) {
      $idps .= " $dir/idp-metadata.xml";
      $server->addProvider(LASSO_PROVIDER_ROLE_IDP, "$dir/idp-metadata.xml");
    }
  }
  error_log ("IdPs:$idps");
  $login = new LassoLogin($server);
} catch (Exception $e) {
  error('Unexpected Lasso error: ' . $e);
  }

try {
  try {
    $login->processAuthnResponseMsg($_POST["SAMLResponse"]);

    $xml = new SimpleXMLElement($login->response->exportToXml());
    $xml_id = $xml->attributes()->{'InResponseTo'};
    if ($id != $xml_id) {
      error_log ("ID parse error: guessed $id got $xml_id");
    }

    if (!file_exists ("$state_path/$id") && !mkdir ("$state_path/$id", 0770)) {
      error ("State management failure (replay?)");
    }

    file_put_contents ("$state_path/$id/samlresp",
		       $login->response->getXmlNode(false));
  } catch (LassoDsError $e) {
    error('Invalid signature');
  } catch (LassoProfileCannotVerifySignatureError $e) {
    error('Invalid signature');
  } catch (LassoError $e) {
    error('Misc error: ' . $e);
  }
  try {
    $ok = $login->acceptSso();
  } catch (LassoError $e) {
    error('Invalid assertion');
  }
} catch (Exception $e) {
  error('Unexpected error: ' . $e);
}

if ($ok != 0) {
  error("acceptSso returned $ok");
}

file_put_contents ("$state_path/$id/subject",
		   $login->assertion->subject->nameId->content);
file_put_contents ("$state_path/$id/success", "");

print "Congratulations!  You are authenticated as: "
. $login->assertion->subject->nameId->content;

print "\n\n<!--\n";
print "\nDecrypted SAML Request:\n";
print "\n";
print $login->response->getXmlNode(false) . "\n";
print "\nBase64-decoded POST Data:\n";
print "\n";
print base64_decode ($_POST["SAMLResponse"]) . "\n";
print "\nEnd of data -->";

?>
