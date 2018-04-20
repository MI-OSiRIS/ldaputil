#!/bin/env python

# common config and methods for our ldap utilities

import ConfigParser
import ldap
import ldap.modlist
import ldap.dn

class LdapUtil:

    def __init__(self, configfile, bind=True):
        config = ConfigParser.SafeConfigParser({
            'objectclass': 'voPerson',
            'uid_attr': 'uid',
            'gid_attr': 'cn',
            'uidnumber_attr': 'uidNumber',
            'gidnumber_attr': 'gidNumber',
            'subj_attr':  'voPersonCertificateDN',
            'ldap_uri': 'localhost',
            'ldap_userdn': None,
            'ldap_groupdn': None,
            'nfs_group_basedn': None,
            'nfs_user_basedn': None,
            'nfs_gss_attr': 'GSSAuthName',
            'nfs_name_attr': 'NFSv4Name',
            'nfs_group_objectclass': 'NFSv4RemoteGroup',
            'nfs_user_objectclass' : 'NFSv4RemotePerson',
        })

        config.read(configfile)

        self.ldap_uri = config.get('server', 'ldap_uri')
        self.ldap_binddn = config.get('server', 'ldap_binddn')
        self.ldap_bindpw = config.get('server', 'ldap_bindpw')
        self.ldap_basedn = config.get('server', 'ldap_basedn')
        self.ldap_userdn = config.get('server', 'ldap_userdn')
        self.ldap_groupdn = config.get('server', 'ldap_groupdn')

        self.objectclass = config.get('schema_cert', 'objectclass')
        self.uid_attr = config.get('schema', 'uid_attr')
        self.gid_attr = config.get('schema', 'gid_attr')
        self.uidnumber_attr = config.get('schema', 'uidnumber_attr')
        self.gidnumber_attr = config.get('schema', 'gidnumber_attr')
        self.subj_attr = config.get('schema_cert','subj_attr')
        self.nfs_group_basedn = config.get('schema_nfs', 'nfs_group_basedn')
        self.nfs_user_basedn = config.get('schema_nfs', 'nfs_user_basedn')
        self.nfs_gss_attr = config.get('schema_nfs', 'nfs_gss_attr')
        self.nfs_name_attr = config.get('schema_nfs', 'nfs_name_attr')
        self.nfs_group_objectclass = config.get('schema_nfs', 'nfs_group_objectclass')
        self.nfs_user_objectclass = config.get('schema_nfs', 'nfs_user_objectclass')

        # defaults we need to set using a setting from the config file
        defaults = { 
            'ldap_userdn': 'ou=People,{0}'.format(self.ldap_basedn),
            'ldap_groupdn': 'ou=Groups,{0}'.format(self.ldap_basedn),
            'nfs_group_basedn': 'ou=NFSGroups,{0}'.format(self.ldap_basedn),
            'nfs_user_basedn': 'ou=NFSPeople,{0}'.format(self.ldap_basedn),
        }

        for attr in [ 'ldap_userdn', 'ldap_groupdn', 'nfs_group_basedn', 'nfs_user_basedn']:
            if getattr(self,attr) == None:
                setattr(self,attr, defaults[attr])

        self.ldap = ldap.initialize(self.ldap_uri)
        if bind:
            self.ldap.bind(self.ldap_binddn,self.ldap_bindpw)
            

    # pass uid * to get all subject DN attributes
    def get_certs(self,uid, subject=None):
        sf = '({0}={1})'.format(self.uid_attr,uid)
        if subject:
            sf = '(&{0}({1}={2}))'.format(sf,self.subj_attr, subject)

        return self.ldap.search_s(self.ldap_userdn,
                                ldap.SCOPE_SUBTREE,
                                sf, 
                                [self.uid_attr,self.subj_attr])

    def rm_cert(self,dn,subject):
        self.ldap.modify_s(dn, [(ldap.MOD_DELETE, 
                            self.subj_attr,
                            subject)])

    def add_cert(self,dn,subject):
        self.ldap.modify_s(dn, [(ldap.MOD_ADD, 
                            self.subj_attr,
                            subject)])

    # returns list of dicts with uidnumber, gidnumber, uid
    # may be empty list of none found for given uid filter
    # easier to deal with than the ldap results directly
    def get_user_attr(self,uid):
        # get the uidNumber / gidNumber
        id_numbers = self.ldap.search_s(self.ldap_userdn,
                            ldap.SCOPE_SUBTREE,
                            '({0}={1})'.format(self.uid_attr, uid),
                            [self.uid_attr,self.uidnumber_attr,self.gidnumber_attr])
        idlist = []

        for object_dn,attr in id_numbers:
            idlist.append({ 
                            'uidnumber': attr[self.uidnumber_attr][0],
                            'gidnumber': attr[self.gidnumber_attr][0],
                            'uid': attr[self.uid_attr][0]
                        })

        return idlist

    def get_group_attr(self,gid):
        id_numbers = self.ldap.search_s(self.ldap_groupdn,
                            ldap.SCOPE_SUBTREE,
                            '({0}={1})'.format(self.gid_attr, gid),
                            [self.gid_attr,self.gidnumber_attr])
        idlist = []

        for object_dn,attr in id_numbers:
            idlist.append({ 
                            'gidnumber': attr[self.gidnumber_attr][0],
                            'gid': attr[self.gid_attr][0]
                        })

        return idlist

    def get_user_mappings(self,uidNumber,gssname=None,nfsname=None):
        sf = '({0}={1})'.format(self.uidnumber_attr,uidNumber)
        if gssname or nfsname:
            sf = '(&' + sf
            if gssname:
                sf = sf + '({0}={1})'.format(self.nfs_gss_attr, gssname)
            if nfsname:
                sf = sf + '({0}={1})'.format(self.nfs_name_attr, nfsname)
            sf = sf + ')'

        return self.ldap.search_s(self.nfs_user_basedn,
                            ldap.SCOPE_SUBTREE,
                            sf,
                            [self.nfs_gss_attr,self.nfs_name_attr,self.uidnumber_attr])
    
    def get_group_mappings(self,gidNumber,nfsname=None):
   
        sf = '({0}={1})'.format(self.gidnumber_attr,gidNumber)

        if nfsname:
            sf = '(&{0}({1}={2}))'.format(sf, self.nfs_name_attr, nfsname)

        return self.ldap.search_s(self.nfs_group_basedn,
                            ldap.SCOPE_SUBTREE,
                            sf,
                            [self.nfs_name_attr, self.gidnumber_attr])

    # returns list of modifications or empty list if no action required
    # decisions here somewhat revolve around ensuring any given GSS name is used only once - the idmap lookup will fail if 2 results are found
    def add_user_mapping(self,uidNumber,gidNumber,gssname,nfsname=None):

        if nfsname == None:
            nfsname = gssname.lower()

        dn = 'cn={0},{1}'.format(nfsname,self.nfs_user_basedn)
       
        # retrieve object(s) with matching GSS user attribute to make sure we don't create a duplicate
        existing = self.get_user_mappings(uidNumber,gssname)

        if len(existing) > 1:
            raise Exception("Found requested GSS name but there are multiple mappings defined between uidNumber {0} and {1} - you must remove the duplicates".format(uidNumber,gssname))

        try:
            for object_dn,attr in existing:
                if nfsname in attr[self.nfs_name_attr]:
                    # this object already matches the specified nfs remote user and has matching GSS name, nothing to do
                    return []
                else:
                    # delete the mapping, may delete entire object if this is the last gss attribute on that object
                    # object will be added later if necessary (this works out simpler than doing logic to rename dn sometimes)
                    self.delete_user_mapping(uidNumber, gssname, attr[self.nfs_name_attr][0])
        except KeyError as e:
            # should be impossible, schema violation (unless using non-default schema?)
            if e.args[0]  == self.nfs_name_attr:
                raise Exception("Found object matching specifed GSS name but it has no attribute {0}".format(self.nfs_name_attr))       

        # retrieve object with matching NFSname to add attribute to (may be none) 
        existing_nfsname = self.get_user_mappings(uidNumber,gssname=None,nfsname=nfsname)

        for object_dn_nfsname,attr_nfsname in existing_nfsname:
            self.ldap.modify_s(object_dn_nfsname, [(ldap.MOD_ADD,
                    self.nfs_gss_attr,
                    gssname)])
            return [(object_dn_nfsname, {
                self.nfs_name_attr: attr_nfsname[self.nfs_name_attr],
                self.nfs_gss_attr: [ gssname ],
                self.uidnumber_attr: attr_nfsname[self.uidnumber_attr] })]

        # if we get this far it's time to create a new object with that GSSname and NFS user 

        attributes = {
            'objectClass': [ 'top', self.nfs_user_objectclass],
            self.uidnumber_attr: [ uidNumber],
            self.gidnumber_attr: [ gidNumber],
            self.nfs_name_attr: [ nfsname ],
            self.nfs_gss_attr: [ gssname ],
            'cn': [ nfsname ]
        }

        attr_modlist = ldap.modlist.addModlist(attributes)

        self.ldap.add_s(dn, attr_modlist)
        return [(dn,attributes)]

    # delete with as much granularity as given by the arguments 
    # up to every usermapping for given uidNumber
    def delete_user_mapping(self,uidNumber,gssname=None,nfsname=None):
        # returns a list of deleted objects
        deleted = list()
        existing = self.get_user_mappings(uidNumber,gssname,nfsname)

        for object_dn,attr in existing:
            if gssname == None and nfsname == None:
                self.ldap.delete_s(object_dn)
                deleted.append((object_dn,attr))
            elif not gssname and nfsname in attr[self.nfs_name_attr]:
                self.ldap.delete(object_dn)
                deleted.append((object_dn,attr))
            elif gssname in attr[self.nfs_gss_attr]:
                # if it's the last GSS attribute remove this object entirely
                if len(attr[self.nfs_gss_attr]) == 1:
                    self.ldap.delete_s(object_dn)
                    deleted.append((object_dn,attr))
                else:
                    self.ldap.modify_s(object_dn, [(ldap.MOD_DELETE,
                                    self.nfs_gss_attr,
                                    gssname)])
                    # create list similar to search results appended in object deletion case
                    deleted.append((object_dn, { 
                        self.nfs_name_attr:  attr[self.nfs_name_attr],
                        self.nfs_gss_attr: [ gssname ],
                        self.uidnumber_attr: attr[self.uidnumber_attr]}))

        return deleted
               
    def add_group_mapping(self,gidNumber,nfsname):
       
        dn = 'cn={0},{1}'.format(nfsname,self.nfs_group_basedn)
        existing = self.get_group_mappings(gidNumber,nfsname)
        # 
        if len(existing) == 1: 
            return []
        if len(existing) > 1:
            raise Exception("Requested mapping exists but there are multiple mappings defined between {0} and {1} with differing CN - please remove duplicates".format(gidNumber,nfsname))
           
        # no existing mappings with that nfs name/uidNumber, create it

        attributes = {
            'objectClass': [ 'top', self.nfs_group_objectclass ],
            self.gidnumber_attr: [ gidNumber ],
            self.nfs_name_attr: [ nfsname] ,
            'cn': [ nfsname ]
        }

        attr_modlist = ldap.modlist.addModlist(attributes)

        self.ldap.add_s(dn, attr_modlist)
        return [(dn, attributes)]

    def delete_group_mappings(self,gidNumber,nfsname):
         # returns a list of deleted objects
        deleted = list()
        existing = self.get_group_mappings(gidNumber,nfsname)

        # we don't really need to match against these results but it doesn't hurt to be sure 
        # (get_group_mappings returns only those matching the filter arguments)
        if len(existing) > 0:
            for object_dn,attr in existing:
                if nfsname == None:
                    self.ldap.delete_s(object_dn)
                    deleted.append((object_dn,attr))
                elif nfsname in attr[self.nfs_name_attr]:
                    self.ldap.delete(object_dn)
                    deleted.append((object_dn,attr))
        return deleted

    def format_user_entries(self,entries):
        for dn,attr in entries:
            for uidnumber in attr[self.uidnumber_attr]:
                for nfsname in attr[self.nfs_name_attr]:
                    print '{0} => {1}'.format(self.nfs_name_attr, nfsname)
                    for gssname in attr[self.nfs_gss_attr]:
                        print '\t{0} => {1}'.format(self.nfs_gss_attr, gssname)

    def format_group_entries(self,entries):
        for dn,attr in entries:
            for gidnumber in attr[self.gidnumber_attr]:
                print '\t{0} => {1}'.format(self.nfs_name_attr,','.join(attr[self.nfs_name_attr]))

    def format_cert_entries(self,entries):
        for object_dn,attr in entries:
            if self.subj_attr in attr:
                print attr[self.uid_attr][0] + ':'
                for cert in attr[self.subj_attr]:
                    print '\t{0}'.format(cert)



