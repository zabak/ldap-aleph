
```
# This is the main slapd configuration file. See slapd.conf(5) for more
# info on the configuration options.

#######################################################################
# Global Directives:

# Features to permit
allow bind_v2

# Schema and objectClass definitions
include         /etc/ldap/schema/core.schema
include         /etc/ldap/schema/cosine.schema
include         /etc/ldap/schema/nis.schema
include         /etc/ldap/schema/inetorgperson.schema
include         /etc/ldap/schema/apple.schema
include         /etc/ldap/schema/samba.schema

TLSCertificateKeyFile   /etc/ldap/certs/ca-key.pem
TLSCertificateFile      /etc/ldap/certs/ca-cert.pem
TLSVerifyClient never

defaultsearchbase "DC=mzk,DC=cz"

# Where the pid file is put. The init.d script
# will not stop the server if you change this.
pidfile         /var/run/slapd/slapd.pid

# List of arguments that were passed to the server
argsfile        /var/run/slapd/slapd.args

# Read slapd.conf(5) for possible values
loglevel        none

# Where the dynamically loaded modules are stored
modulepath      /usr/lib/ldap
moduleload      back_bdb
moduleload      back_ldap
moduleload      back_meta

# The maximum number of entries that is returned for a search operation
sizelimit 500

# The tool-threads parameter sets the actual amount of cpu's that is used
# for indexing.
tool-threads 1

backend ldap

database ldap
subordinate
suffix ou=readers,dc=mzk,dc=cz
uri ldap://localhost:8000/
acl-bind bindmethod=simple
idassert-bind none
access to attrs=userPassword,aleph-id
  by self      read
access to *
  by *         read

database   bdb
suffix     "dc=mzk,dc=cz"
#suffix     "ou=macosxodconfig,dc=mzk,dc=cz" "ou=mounts,dc=mzk,dc=cz"
checkpoint 512 30
directory  "/var/lib/ldap"
dbconfig   set_cachesize 0 2097152 0
dbconfig   set_lk_max_objects 1500
dbconfig   set_lk_max_locks 1500
dbconfig   set_lk_max_lockers 1500
index      objectClass eq
lastmod    on
access     to attrs=userPassword,shadowLastChange
              by dn="cn=admin,dc=mzk,dc=cz" write
              by anonymous auth
              by self write
              by * none
access     to dn.base="" by * read
access     to * by dn="cn=admin,dc=mzk,dc=cz" write by * read
```