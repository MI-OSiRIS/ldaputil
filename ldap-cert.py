#! /bin/env python

# This is intentionally limited to a very specific use-case with CILogon certificates
# The voPerson ldap schema requires these be stored in ldap style: CN=Pat Lee A251,O=Example,C=US,DC=cilogon,DC=org
# The script is not smart about reordering subject attributes so provide them in valid order depending on format

# simple class to share config init and some common calls among utils 
from ldaputil import LdapUtil
import argparse
from argparse import RawDescriptionHelpFormatter
import sys
import os
import re

certhelp = "This util only accepts CILogon certs in these formats:\n/DC=org/DC=cilogon/C=US/O=Example/CN=Common Name\nCN=Common Name,O=Exampe,C=US,DC=cilogon,DC=org"

def_config = os.path.dirname(os.path.realpath(sys.argv[0])) + '/ldaputil.conf'

parser = argparse.ArgumentParser(description='Add new LDAP subject DN under voPerson attribute voPersonCertificateDN',
                                 epilog=certhelp,
                                 formatter_class=RawDescriptionHelpFormatter)

def dncheck(s):
    # hard-coding cilogon org until reason otherwise 
    cilogon_dnregex = re.compile(r"/DC=org/DC=cilogon/C=[A-Z]{2}/O=.+/CN=.+")
    ldap_dnregex = re.compile(r"CN=.+,O=.+,C=[A-Z]{2},DC=cilogon,DC=org")

    if ldap_dnregex.match(s) or args.relax:
        return s
    elif cilogon_dnregex.match(s):
        ldap_value = s.split('/')
        ldap_value.remove('')
        ldap_value.reverse()
        return ','.join(ldap_value)
    else:
        parser.error(certhelp)

parser.add_argument('--delete', 
                    action='store_true', 
                    help='Delete specified DN from uid.  Default is to add.')

parser.add_argument('--relax',
                    action='store_true',
                    help='Do not perform checks or formatting on subject DN.  Intended for deleting malformed entries or testing.')

parser.add_argument('-c', '--config', 
                    default=def_config,
                    help='Optional path to config file (default {0})'.format(def_config))

parser.add_argument('-l', '--list',
                    action='store_true',
                    help='List all uid with subj_attr from LDAP directory (ignores uid and dn args)')

parser.add_argument('uid',
                    help='User name string matching configured uid_attr in LDAP directory',
                    nargs='?')

parser.add_argument('dn', 
                    help='Subject DN string to be associated with uid in LDAP directory',
                    nargs='?') 

args = parser.parse_args()

ldap = LdapUtil(args.config)

# a little redundant but makes for cleaner output and logic 
if args.list:
    cert_list = ldap.get_certs('*')
    for object_dn,attr in cert_list:
        if ldap.subj_attr in attr:
            print attr[ldap.uid_attr][0] + ':'
            for cert in attr[ldap.subj_attr]:
                print '   => {0}'.format(cert)
    sys.exit(0)

else:
    if not (args.dn and args.uid):
        parser.error("dn and uid are required unless --list is specified")
    insert_cert = dncheck(args.dn)
    cert_list = ldap.get_certs(args.uid)

if len(cert_list) == 0:
    print "Error: No object with attr {0} matching {1} in {2}".format(ldap.uid_attr,args.uid,ldap.ldap_userdn)
    sys.exit(1)

if len(cert_list) > 1:
    print "Error: Found more than one result with attr {0} matching {1} in {2} (this should not be possible)?".format(uid_attr,args.uid,ldap_userdn)
    sys.exit(1)

for object_dn,cert_dn in cert_list:

    print '\nFound object: {0}'.format(object_dn)
    try:
        for idx, certdn_value in enumerate(cert_dn[ldap.subj_attr], start=1):
            if certdn_value == insert_cert:
                print 'Found {0}: {1}'.format(ldap.subj_attr, certdn_value)
                if args.list:
                    continue
                if args.delete:
                    print '=> Deleting'
                    ldap.rm_cert(object_dn,certdn_value)
                    break
                else:
                    print '=> No action required'
                    break
            # not found, raise KeyError same as if no attribute found
            if idx == len(cert_dn[ldap.subj_attr]):
                raise KeyError
    except KeyError:
        if args.list:
            continue
        print 'Did not find {0}'.format(ldap.subj_attr)
        if not args.delete:
            print '=> Adding: {0}'.format(insert_cert)
            ldap.add_cert(object_dn,insert_cert)

