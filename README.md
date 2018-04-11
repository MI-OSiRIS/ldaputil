# ldaputil
Misc LDAP utilities used in OSiRIS 



## Globus and CILogon utilities

Tools related to managing CIlogon certificate subject DN attributes for LDAP users.  Defaults to using voPersonCertificateDN from voPerson schema but these are configurable.

 * ldap-cert.py
 
 Add, list, or delete CILogon certificate subject DN, list uid and subjects.

 * ldap-mapfile.py

Generate Globus grid-mapfile from ldap.  Synchronizes gridmap entries with LDAP for any uid found in LDAP - gridmap entries which are not in LDAP will be deleted for those uid.  If uid in grid-mapfile does not exist in LDAP it is left as-is.  Default mapfile input and output is /etc/grid-security/grid-mapfile.  Input and output file can be specified with options and do not have to be the same file.  

## NFSv4 Utilities

Tools related to managing NFSv4 GSS auth lookup and name mapping with idmapd.conf 'umich_ldap' configuration.

* ldap-nfs.py

Add, list, or delete GSS auth names, remote users, and remote groups.  LDAP attributes used are configurable but default to same attributes as in default idmapd config.  This utility does not allow for setting NFSv4 remote user mappings that do not also have a GSS name to map to.  

## Config

* ldaputil.py

Module defining LdapUtil for common config and methods.  

* ldaputil.conf

Defines configuration for utils, read by LdapUtil module.  Defaults location is same directory as script.

Example config included in this repository has comments explaining each option.

## Usage

```
usage: ldap-cert.py [-h] [--delete] [--relax] [-c CONFIG] [-l] [uid] [dn]

Add new LDAP subject DN under voPerson attribute voPersonCertificateDN

positional arguments:
  uid                   User name string matching configured uid_attr in LDAP
                        directory
  dn                    Subject DN string to be associated with uid in LDAP
                        directory

optional arguments:
  -h, --help            show this help message and exit
  -d, --delete              Delete specified DN from uid. Default is to add.
  --relax               Do not perform checks or formatting on subject DN.
                        Intended for deleting malformed entries or testing.
  -c CONFIG, --config CONFIG
                        Optional path to config file (default
                        ldaputil.conf)
  -l, --list            List all uid with subj_attr from LDAP directory
                        (ignores uid and dn args)

This util only accepts CILogon certs in these formats:
/DC=org/DC=cilogon/C=US/O=Example/CN=Common Name
CN=Common Name,O=Exampe,C=US,DC=cilogon,DC=org
```

```
usage: ldap-mapfile.py [-h] [-c CONFIG] [-m MAPFILE] [-o OUTPUT] [-f]

Regenerate Globus grid-mapfile from LDAP directory

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Optional path to config file (default
                        ldaputil.conf)
  -m MAPFILE, --mapfile MAPFILE
                        Optional path to Globus grid-mapfile (default /etc
                        /grid-security/grid-mapfile)
  -o OUTPUT, --output OUTPUT
                        Optional path to output file (default is same location
                        specified by --mapfile
  -f, --force           Force writing out file even if no changes found
```

```
usage: ldap-nfs.py [-h] [-c CONFIG] [-l] [-g] [-u USER] [-d] [id] [mapping]

Utility to add GSSAuthName, NFSv4Name, NFSv4RemoteGroup to ldap

positional arguments:
  id                    User or group name string matching configured uid_attr
                        or gid_attr in LDAP directory
  mapping               Kerberos principal or NFSv4 remote group to be added
                        to id

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Optional path to config file (default
                        ldaputil.conf)
  -l, --list            List mappings for user argument or all users if none
                        specified
  -g, --group           Assign or list NFSv4 group mapping to id argument (default is
                        to assign Kerberos principal set by mapping arg)
  -u USER, --user USER  NFSv4 user mapping (user@idmap.domain.example). If not
                        provided for a Kerberos mapping then the lowercased
                        mapping value is used.
  -d, --delete          Delete specified principal/group/remote user mapping
                        (depending on args)
```

## Examples 

Add certificate:
```
ldap-cert.py user "/DC=org/DC=cilogon/C=US/O=University of Example/CN=Example User A1234"
```

Delete cert for user (leave off subject to delete all user certs):
```
ldap-cert.py -d user "/DC=org/DC=cilogon/C=US/O=University of Example/CN=Example User A1234"
```

Generate mapfile (no options are required if reading/writing to default location):
```
ldap-mapfile.py --mapfile /alt/location/grid-mapfile --output /etc/grid-security/grid-mapfile
```

Add /delete new GSS mapping for user@EXAMPLE.EDU.  The util will default to setting the NVSv4 idmap remote user to user@example.edu if not provided:
```
ldap-nfs.py myuser user@EXAMPLE.EDU

ldap-nfs.py -d myuser user@EXAMPLE.EDU
```

Delete all mappings for user:
```
ldap-nfs.py -d myuser
```

Add / remove new remote user GSS name and id mapping:  
```
ldap-nfs.py myuser user@EXAMPLE.EDU -u someuser@example2.edu

ldap-nfs.py -d myuser user@EXAMPLE.EDU -u someuser@example2.edu
```

Add new remote group mapping:
```
ldap-nfs.py -g mygroup somegroup@example.edu
```







