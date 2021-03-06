<?php
error_reporting(E_ERROR | E_WARNING | E_PARSE);

include "./Security/Exception/ExceptionInterface.php";
include "./Security/Exception/LogicException.php";
include "./Security/Utilities/NumberUtilitiesTrait.php";
include "./Security/Utilities/LdapUtilities.php";

include "./Security/Acl/Acl.php";
include "./Security/Acl/Dacl.php";
include "./Security/Acl/Sacl.php";

include "./Security/Flags.php";
include "./Security/FlagsSddlTrait.php";
include "./Security/GUID.php";
include "./Security/SddlParser.php";
include "./Security/SID.php";
include "./Security/SecurityDescriptor.php";
include "./Security/ControlFlags.php";

include "./Security/Ace/Ace.php";
include "./Security/Ace/AceFlags.php";
include "./Security/Ace/AceObjectFlags.php";
include "./Security/Ace/AceRights.php";
include "./Security/Ace/AceType.php";

use LdapTools\Security\SecurityDescriptor;
use LdapTools\Security\Acl\Dacl;
use LdapTools\Security\Ace\AceType;
use LdapTools\Security\Ace\Ace;
use LdapTools\Security\Ace\AceFlags;

include "Helpers/LdapConnection.php";


function connectToLDAP($ip, $dc, $username, $password)
{
  $connection = ldap_connect("ldaps://{$ip}:636");
  $LDAP_USER = $username."@".$dc;
  ldap_set_option ($connection, LDAP_OPT_REFERRALS, 0);
  ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
  $ldapbind = ldap_bind($connection, $LDAP_USER, $password);

  if($connection){
    if($ldapbind) {
      echo "\n\033[92m[+] \033[0m";
      echo "\033[36mLDAP Bind Successfull. \033[0m\n";
    }
  }

  $ldap = new LdapConnection($dc);

  return $connection;
}

function getNTSecDesc($connection, $computerName, $targetDN)
{
  $attributes = array("ntsecuritydescriptor");
  $filter = "(&(name={$computerName}))";
  $result = ldap_search($connection, $targetDN, $filter, $attributes);
  $data = ldap_get_entries($connection, $result);
  $dacl = $data[0]["ntsecuritydescriptor"][0];


  echo "\033[92m[+] \033[0m";
  echo "\033[36mFetching the NTSecurityDescriptor value of the target computer: \033[0m";
  echo "\033[93m{$computerName} \033[0m";

  return base64_encode($dacl);
}

function daclParser($b64dacl)
{
  $securityDecriptor = base64_decode($b64dacl);
  $sd = new SecurityDescriptor($securityDecriptor);

  $dacl = $sd->getDacl() ? $sd->getDacl() : new Dacl();
  $sd->setDacl($dacl);

  $data = [
    "owner" => (object)[
        "sid" => $sd->getOwner()->toString(),
        "name" => $sd->getOwner()->toString()
    ],
    "group" => (object)[
        "sid" => $sd->getGroup()->toString(),
        "name" => $sd->getGroup()->toString()
    ],
    "aces" => $sd->getDacl()->getAces() ? [] : new stdClass(),
    "trustees" => $sd->getDacl()->getAces() ? [] : new stdClass()
  ];
  foreach ($sd->getDacl()->getAces() as $ace) {
      $trustee = $ace->getTrustee()->toString();
      $data["trustees"][$ace->getTrustee()->toString()] = $trustee;
      $data["aces"][$ace->getTrustee()->toString()][] = (object)[
          "type" => (string) array_search($ace->getType()->getValue(), AceType::TYPE),
          "trustee" => (object)[
              "sid" => $ace->getTrustee()->toString(),
              "name" => $trustee
          ],
          "isAllowAce" => $ace->isAllowAce(),
          "rights" => [
              "readGroup" => $ace->getRights()->readGroup(),
              "writeGroup" => $ace->getRights()->writeGroup(),
              "readProperty" => $ace->getRights()->readProperty(),
              "readSecurity" => $ace->getRights()->readSecurity(),
              "listChildObject" => $ace->getRights()->listChildObject(),
              "writeProperty" => $ace->getRights()->writeProperty(),
              "validatedWrite" => $ace->getRights()->validatedWrite(),
              "deleteTree" => $ace->getRights()->deleteTree(),
              "createChildObject" => $ace->getRights()->createChildObject(),
              "deleteChildObject" => $ace->getRights()->deleteChildObject(),
              "deleteObject" => $ace->getRights()->deleteObject(),
              "listObject" => $ace->getRights()->listObject(),
              "controlAccess" => $ace->getRights()->controlAccess(),
              "writeDacl" => $ace->getRights()->writeDacl(),
              "writeOwner" => $ace->getRights()->writeOwner(),
              "readAll" => $ace->getRights()->readAll(),
              "writeAll" => $ace->getRights()->writeAll(),
              "execute" => $ace->getRights()->execute(),
              "fullControl" => $ace->getRights()->fullControl(),
              "synchronize" => $ace->getRights()->synchronize(),
          ],
          "flags" => $ace->getFlags() ? $ace->getFlags()->getValue() : null,
          "objectType" => $ace->getObjectType() ? $ace->getObjectType()->toString() : null,
          "inheritedObjectType" => $ace->getInheritedObjectType() ? $ace->getInheritedObjectType()->toString() : null
      ];
  }


  $to_add_1 = json_decode('{"type":"ACCESS_ALLOWED_OBJECT","trustee":{"sid":"S-1-5-10","name":"S-1-5-10"},"isAllowAce":true,"rights":{"readGroup":false,"writeGroup":false,"readProperty":true,"readSecurity":false,"listChildObject":false,"writeProperty":true,"validatedWrite":false,"deleteTree":false,"createChildObject":false,"deleteChildObject":false,"deleteObject":false,"listObject":false,"controlAccess":false,"writeDacl":false,"writeOwner":false,"readAll":false,"writeAll":false,"execute":false,"fullControl":false,"synchronize":false},"flags":2,"objectType":"3e978925-8c01-11d0-afda-00c04fd930c9","inheritedObjectType":null}');
    
  $to_add_2 = json_decode('{"type":"ACCESS_ALLOWED","trustee":{"sid":"S-1-5-10","name":"S-1-5-10"},"isAllowAce":true,"rights":{"readGroup":false,"writeGroup":false,"readProperty":false,"readSecurity":false,"listChildObject":false,"writeProperty":true,"validatedWrite":false,"deleteTree":false,"createChildObject":false,"deleteChildObject":false,"deleteObject":false,"listObject":false,"controlAccess":false,"writeDacl":false,"writeOwner":false,"readAll":false,"writeAll":false,"execute":false,"fullControl":false,"synchronize":false},"flags":2,"objectType":null,"inheritedObjectType":null}');

  if (!in_array($to_add_1, $data["aces"]["S-1-5-10"]))
  {
    array_push($data["aces"]["S-1-5-10"], $to_add_1);
  }

  if (!in_array($to_add_2, $data["aces"]["S-1-5-10"]))
  {
    array_push($data["aces"]["S-1-5-10"], $to_add_2);
  }


  $data = (object) $data;
  if($data->owner){
      $sd->setOwner($data->owner->sid);
      if(!$sd->getGroup()){
          $sd->setGroup($data->owner->sid);
      }
  }

  $dacl = $sd->getDacl() ? $sd->getDacl() : new Dacl();

  $sd->setDacl($dacl);
  
  $sd->getDacl($dacl)->setAces([]);

  foreach($data->aces as $trustee => $aces){
    foreach($aces as $ace){
        $aceType= array_search(AceType::TYPE[$ace->type], AceType::SHORT_NAME);
        $aceObject = new Ace($aceType);
        $aceObject->setTrustee($trustee);
        $aceObject->setFlags(new AceFlags($ace->flags));
        if($ace->objectType){
            $aceObject->setObjectType($ace->objectType);
        }
        if($ace->inheritedObjectType){
            $aceObject->setInheritedObjectType($ace->inheritedObjectType);
        }
        $isAllFalse = true;
        foreach($ace->rights as $key => $value){
            if($value){
                $isAllFalse = false;
            }
            $aceObject->getRights()->{$key}((bool)$value);
        }
        if(!$isAllFalse){
            $sd->getDacl($dacl)->addAce($aceObject);
        }
    }
  }

  echo "\n\033[92m[+] \033[0m";
  echo "\033[36mSDDL is parsed and new attributes are added. \033[0m";

  return $sd;
}

function setNewDacl($computerName, $sd, $conn)
{
  ldap_mod_replace($conn, $computerName, [
    "nTSecurityDescriptor" => $sd->toBinary()
  ]);

  echo "\n\033[92m[+] \033[0m";
  echo "\033[36mNew NtSecurityDescriptor value set on the target computer: \033[0m";
  echo "\033[93m{$computerName} \033[0m";

}

function getComputers($conn, $basedn, $filter, $attributes=array("ou"))
{
  $searchResult = ldap_search($conn, $basedn, $filter, $attributes);
  $entries = ldap_get_entries($conn, $searchResult);
  $computers = array();

  for($i=0; $i<count($entries); $i++) {
    if($entries[$i]["dn"]){
      array_push($computers, $entries[$i]["dn"]);
    }
  }

  return $computers;
}

function setReadOSPermForEveryComputer($ip, $dc, $username, $password, $base_dn, $additional_filters){
  $dc_parts = explode(".", $dc);

  if($base_dn == null) {
    $basedn="";
    foreach($dc_parts as $part){
      $basedn .= "DC={$part},";
    }
    $basedn = substr_replace($basedn, "", -1);
  } else {
    $basedn = $base_dn;
  }
  
  echo "\n\033[92m[+] \033[0m";
  echo "\033[36mDetected Base DN: {$basedn} \033[0m";

  echo "\n\033[92m[+] \033[0m";
  echo "\033[36mFilter for LDAP search: \033[0m";
  echo "\033[93m(&(objectclass=computer){$additional_filters})\033[0m";

  $conn = connectToLDAP($ip, $dc, $username, $password);

  $computerList = getComputers($conn, $basedn, "(&(objectclass=computer){$additional_filters})");
  
  echo "\033[34m\n-------------------------------- \033[0m\n";  
  echo "\033[92mFounded Computers: \033[0m\n\n";
  foreach ($computerList as $computer) {
    echo "\033[35m => \033[0m";
    echo "\033[93m$computer\033[0m\n";
  }
  echo "\033[34m-------------------------------- \033[0m\n";  

  foreach($computerList as $computer)
  {
    echo "\033[92m\n-------------------------------- \033[0m\n";  
    $justComputer = explode("=",explode(",", $computer)[0])[1];
    $dacl = getNTSecDesc($conn, $justComputer, $basedn);
    $sd = daclParser($dacl);
    setNewDacl($computer, $sd, $conn);
    echo "\033[92m\n-------------------------------- \033[0m\n";  
  }
}

$opts = "";
$opts .= "b:";
$opts .= "i:";
$opts .= "u:";
$opts .= "p:";
$opts .= "d:";
$opts .= "f:";

$optSettings = array(
  "required:",
);

$options = getopt($opts, $optSettings);

if (!$options["d"]){
  $options["d"] = null;
}

if (!$options["f"]){
  $options["f"] = "";
}


setReadOSPermForEveryComputer($options["i"], $options["b"], $options["u"], $options["p"], $options["d"], $options["f"]);
