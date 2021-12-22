<?php
class LdapConnection
{
    private $connection;
    private $dn = "";
    private $isAD = true;
    private $domain = "";
    private $currentIp = null;
    private $fqdn = "";


    public function __construct($domain_name = null)
    {
        try {
            $connection = ldap_connect("ldap://".$domain_name.":389");
            ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_bind($connection);
            $outputs = ldap_read($connection,'','objectclass=*');
            $entries = ldap_get_entries($connection,$outputs)[0];
            $this->fqdn = (array_key_exists("dnshostname",$entries)) ? $entries["dnshostname"][0] : "";
            $this->isAD = (array_key_exists("domainfunctionality",$entries)) ? true : false;
            $this->domain = $entries['rootdomainnamingcontext'][0];
        } catch (Exception $e) {
            dd($e->getMessage());
        } 
    }

    public function getConnection()
    {
        return $this->connection;
    }

    public function getAttributes($cn, $attr=null)
    {
        $cn = ldap_escape($cn);
        if($attr){
            $search = ldap_search($this->connection, $this->domain, '(distinguishedname=' . $cn . ')', $attr);
        }else{
            $search = ldap_search($this->connection, $this->domain, '(distinguishedname=' . $cn . ')');
        }
        $first = ldap_first_entry($this->connection,$search);
        return ldap_get_attributes($this->connection,$first);
    }


    public function updateAttributes($cn, $array)
    {
        $toUpdate = [];
        $toDelete = [];
        foreach($array as $key=>$item){
            if($item == null){
                $toDelete[$key] = array();
                continue;
            }
            $toUpdate[$key] = $item;
        }
        $flagUpdate = true;
        $flagDelete = true;
        if(count($toUpdate)){
            $flagUpdate = ldap_mod_replace($this->connection,$cn,$toUpdate);
        }

        if(count($toDelete)){
            $flagDelete = ldap_modify($this->connection,$cn,$toDelete);
        }
        
        return $flagUpdate && $flagDelete;
    }
}