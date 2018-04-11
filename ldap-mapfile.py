#!/bin/env python

# rebuild grid-mapfile using certificate subject DN queried from LDAP
# for uid found in LDAP the entry there will be authoratitive
# this util removes any mapfile entries not found in ldap 
# If there is no matching uid in ldap the mapfile entry is left as-is 
# 
# Note: can use Globus util 'grid-mapfile-check-consistency' to check file after

from ldaputil import LdapUtil
import argparse
import sys
import os

parser = argparse.ArgumentParser(description='Regenerate Globus grid-mapfile from LDAP directory')

def_mapfile='/etc/grid-security/grid-mapfile'
def_config = os.path.dirname(os.path.realpath(sys.argv[0])) + '/ldaputil.conf'

parser.add_argument('-c', '--config', 
                    default=def_config,
                    help='Optional path to config file (default {0})'.format(def_config))

parser.add_argument('-m', '--mapfile',
                    default=def_mapfile,
                    help='Optional path to Globus grid-mapfile (default {0})'.format(def_mapfile))

parser.add_argument('-o', '--output',
                    help='Optional path to output file (default is same location specified by --mapfile')

parser.add_argument('-f', '--force',
                    action='store_true',
                    help='Force writing out file even if no changes found')

args = parser.parse_args()

ldap = LdapUtil(args.config)

mapfile = open(args.mapfile, 'r')

subject_list = ldap.get_certs('*')

if len(subject_list) == 0:
    print "Error: No object with attr {0} matching {1} in {2}".format(ldap.uid_attr,args.uid,ldap.ldap_userdn)
    sys.exit(1)

mapfile_lines = mapfile.readlines()

# variable set to trigger writing out new file if there are changes
update = False

for object_dn,attr in subject_list:
    try:
        # match only lines with same uid (last word)
        user_mapfile_lines = filter(lambda x: attr[ldap.uid_attr][0] in x.rsplit(' ', 1)[-1], mapfile_lines)

        # remove those lines - whatever we find in LDAP is master (sets are cool!)
        mapfile_lines = set(mapfile_lines) - set(user_mapfile_lines)

        for certdn_value in attr[ldap.subj_attr]:
            print 'LDAP => {0}: {1}'.format(attr[ldap.uid_attr][0], certdn_value)
            # turn this into the format used in grid-mapfile
            ms = certdn_value.split(',')
            ms.reverse()
            mapfile_subject = '/' + '/'.join(ms)
            mapfile_entry = '"{0}" {1}\n'.format(mapfile_subject, attr[ldap.uid_attr][0])
            # print "contsructed entry: {0}".format(mapfile_entry)
            if mapfile_entry in user_mapfile_lines:
                print 'Mapfile => found match\n'
                # any lines left in the list after this loop were not found in LDAP
                user_mapfile_lines.remove(mapfile_entry)
            else:
                print 'Mapfile => inserting new\n'
                update = True
            mapfile_lines.add(mapfile_entry)

        for rline in user_mapfile_lines:
            print 'Mapfile => removed {0}'.format(rline)
            update = True

    except KeyError:
        pass
        # object missing subject dn attr, move on (could print it but I don't think that's useful)
        # print 'LDAP => Did not find any {0} for uid {1}\n'.format(ldap.subj_attr, attr[ldap.uid_attr][0])

if args.output:
    outfile = args.output
else:
    outfile = args.mapfile

mapfile.close()

if update or args.force:
    print "=> Writing file to {0}".format(outfile)
    mapfile = open(outfile, 'w+')
    mapfile.writelines(sorted(mapfile_lines))
    mapfile.close()
else:
    print "=> No changes required, not writing out file"

