#! /bin/env python

# utility to add GSSAuthName, NFSv4Name, NFSv4RemoteGroup to ldap
# given userid will lookup uid/gidNumber.  
# intentionally a little backwards in requiring GSS name because it is useless  
# in our context to have a name mapping without the GSS attribute
# LDAP object doesn't require GSS attr but does require NFSv4RemoteUser

# simple class to share config init and some common calls among utils 
from ldaputil import LdapUtil
import argparse
from argparse import RawDescriptionHelpFormatter
import sys
import os
import re

parser = argparse.ArgumentParser(description='Utility to add GSSAuthName, NFSv4Name, NFSv4RemoteGroup to ldap')

def_config = os.path.dirname(os.path.realpath(sys.argv[0])) + '/ldaputil.conf'

parser.add_argument('-c', '--config', 
                    default=def_config,
                    help='Optional path to config file (default {0})'.format(def_config))


action = parser.add_mutually_exclusive_group()

action.add_argument('-d', '--delete',
                    action='store_true',
                    help='Delete specified principal/group/remote user mapping (depending on args)')

action.add_argument('-l', '--list',
                    action='store_true',
                    help='List mappings for user argument or all users if none specified')

parser.add_argument('-g', '--group',
                    action='store_true',
                    help='Assign or list NFSv4 group mapping to id argument (default is to assign Kerberos principal set by mapping arg)')

parser.add_argument('-u', '--user',
                    default=None,
                    help='NFSv4 user mapping (user@idmap.domain.example).  If not provided for a Kerberos mapping then the lowercased mapping value is used.')

parser.add_argument('id',
                    nargs='?',
                    help='User or group name string matching configured uid_attr or gid_attr in LDAP directory')

parser.add_argument('mapping',
                    help='Kerberos principal or NFSv4 remote group to be added to id',
                    nargs='?')

args = parser.parse_args()

ldap = LdapUtil(args.config)

question = lambda q: raw_input(q).lower().strip()[0] == "y" or sys.exit(0)

if not (args.delete or args.mapping or args.list):
    parser.error('Argument "mapping" required')

if not (args.list or args.id):
    parser.error('Argument "id" required')

if args.list and args.id == None:   
    args.id = '*'
   
if args.group:
    idnumbers = ldap.get_group_attr(args.id)
    if not idnumbers:
        print 'LDAP => Group {0} was not found in {1}'.format(args.id,ldap.ldap_groupdn)
        sys.exit(1)
else:
    idnumbers = ldap.get_user_attr(args.id)
    if not idnumbers: 
        print 'LDAP => User {0} was not found in {1}'.format(args.id,ldap.ldap_userdn)
        sys.exit(1)

if not args.user and not args.list and not args.delete:
        print 'Using {0} as NFSv4 user mapping'.format(args.mapping.lower())

for d in idnumbers:
    # get a list of entries matching arguments to confirm delete 
    if args.list or args.delete:
        op = 'Showing'
        if args.group:
            entries = ldap.get_group_mappings(d['gidnumber'],args.mapping)
        else:
            entries = ldap.get_user_mappings(d['uidnumber'], args.mapping, args.user)
        if len(entries) == 0:
            continue
    if args.delete:
        op = 'Deleted'
        if len(entries) > 1:
            ldap.format_group_entries(entries) if args.group else ldap.format_user_entries(entries)
            question('This will delete multiple entries, confirm delete (y/n): ')
        if args.group:
            entries = ldap.delete_group_mappings(d['gidnumber'],args.mapping)
        else:
            entries = ldap.delete_user_mapping(d['uidnumber'], args.mapping, args.user)
    elif not args.list:
        op = 'Added'
        if args.group:
            entries = ldap.add_group_mapping(d['gidnumber'],args.mapping)
        else:
            entries = ldap.add_user_mapping(d['uidnumber'], d['gidnumber'], args.mapping, args.user)

    if len(entries) == 0:
        print 'LDAP => Mapping exists, no action required'
        sys.exit(0)

    if args.group:
        print 'LDAP => {0} mappings for {1}:'.format(op,d['gid'])
        ldap.format_group_entries(entries)
    else: 
        print 'LDAP => {0} mappings for {1}:'.format(op,d['uid'])
        ldap.format_user_entries(entries)
