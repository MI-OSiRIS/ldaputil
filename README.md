# ldaputil
Misc LDAP utilities used in OSiRIS related to managing CIlogon certificate subject DN attributes for LDAP users.  Defaults to using voPersonCertificateDN from voPerson schema but these are configurable.

## Utilities

 * ldap-cert.py
 
 Add or delete CILogon certificate subject DN, list uid and subjects.

 * ldap-mapfile.py

Generate Globus grid-mapfile from ldap.  Synchronizes gridmap entries with LDAP for any uid found in LDAP - gridmap entries which are not in LDAP will be deleted for those uid.  If uid in grid-mapfile does not exist in LDAP it is left as-is.  Default mapfile input and output is /etc/grid-security/grid-mapfile.  Input and output file can be specified with options and do not have to be the same file.  

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
  --delete              Delete specified DN from uid. Default is to add.
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

## Example 

Add certificate:
```
ldap-cert.py user "/DC=org/DC=cilogon/C=US/O=University of Example/CN=Example User A1234"
```

Generate mapfile (no options are required if reading/writing to default location):
```
ldap-mapfile.py --mapfile /alt/location/grid-mapfile --output /etc/grid-security/grid-mapfile
```







