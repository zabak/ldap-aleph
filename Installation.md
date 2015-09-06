# Prerequisites #
  * Aleph X-Services
  * Perl with these packages: Net::LDAP, Net::LDAP::Server, LWP, XML::Simple, URI, Digest, Crypt, DBI, IO.

# Installation #

  1. Create a user account in oracle db for ldap and run this statements:
```
  CREATE SEQUENCE pas00.uids START WITH 1000 INCREMENT BY 1;

  CREATE TABLE pas00.uuids (
    ID        CHAR(12) REFERENCES pas00.z308,
    UUID      NUMBER   PRIMARY KEY,
    ENTRYUUID VARCHAR2(50) NOT NULL
  );
```
  1. Configure LDAPServerConfig.pm:
```
  sub load {
      my %config = ();
      # port on which ldap server is running
      $config{'server.port'} = 8000;
      $config{'db.url'} = 'dbi:Oracle:host=zeus;SID=aleph20;';
      $config{'db.user'} = 'db user';
      $config{'db.password'} = 'db passsword';
      $config{'ldap.base_dn'} = 'dc=mzk,dc=cz';
      $config{'aleph.host'} = 'aleph.mzk.cz';
      $config{'aleph.user'} = 'YOUR-WWW-X-USER';
      $config{'aleph.password'} = 'YOUR-WWW-X-USER-PASSWORD';
      $config{'aleph.adm_lib'} = 'MZK50';
      $config{'dn:ou=shibboleth,dc=mzk,dc=cz'} = \&shibboleth_filter,
      $config{'dn:ou=readers,dc=mzk,dc=cz'} = \&readers_filter,
      $config{'dn:ou=test,dc=mzk,dc=cz'} = \&shibboleth_filter,
      return \%config;
  }
```
  1. Start LDAP server:
```
  nohup ./ldap_server.pl &
```
  1. Test LDAP server:
```
  ldapsearch -H "ldap://localhost:8000" "(uid=user)" -x
```