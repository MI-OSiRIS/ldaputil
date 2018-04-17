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

question = lambda q: raw_input(q).lower().strip()[0] == "y" or sys.exit(0)

action = parser.add_mutually_exclusive_group()

action.add_argument('-d', '--delete', 
                    action='store_true', 
                    help='Delete specified DN from uid.  Default is to add.')

action.add_argument('-l', '--list',
                    action='store_true',
                    help='List all uid with subj_attr from LDAP directory')

parser.add_argument('--relax',
                    action='store_true',
                    help='Do not perform checks or formatting on subject DN.  Intended for deleting malformed entries or testing.')

parser.add_argument('-c', '--config', 
                    default=def_config,
                    help='Optional path to config file (default {0})'.format(def_config))

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
    if args.uid == None:
        args.uid = '*'
    cert_list = ldap.get_certs(args.uid,args.dn)
    ldap.format_cert_entries(cert_list)
    sys.exit(0)

else:
    if not args.uid and not args.list:
        parser.error("uid is required unless --list is specified")
    if not (args.uid and args.dn) and not (args.list or args.delete):
        parser.error("uid and dn are required unless --list or --delete specified")

    if args.dn:
        insert_cert = dncheck(args.dn)
    else:
        insert_cert = None

    cert_list = ldap.get_certs(args.uid)

if len(cert_list) == 0:
    print "Error: No object with attr {0} matching {1} in {2}".format(ldap.uid_attr,args.uid,ldap.ldap_userdn)
    sys.exit(1)

for object_dn,cert_dn in cert_list:

    print '\nFound object: {0}'.format(object_dn)
    try:
        if args.delete and insert_cert == None:
            question('Confirm delete all {0} for object (y/n)? '.format(ldap.subj_attr))
        for idx, certdn_value in enumerate(cert_dn[ldap.subj_attr], start=1):
            if certdn_value == insert_cert or (args.delete and insert_cert == None):
                print 'Found {0}: {1}'.format(ldap.subj_attr, certdn_value)
                if args.delete:
                    print '=> Deleting'
                    ldap.rm_cert(object_dn,certdn_value)
                    if idx == len(cert_dn[ldap.subj_attr]):
                        break
                else:
                    print '=> No action required'
                    break
            # not found, raise KeyError same as if no attribute found
            if idx == len(cert_dn[ldap.subj_attr]):
                raise KeyError('No attribute {0} matched dn'.format(ldap.subj_attr))
    except KeyError as e:
        if e.args[0] == ldap.subj_attr: 
            print 'Did not find attribute {0}'.format(ldap.subj_attr)
        else:
            print e.args[0]

        if not args.delete:
            print '=> Adding: {0}'.format(insert_cert)
            ldap.add_cert(object_dn,insert_cert)

