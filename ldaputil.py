#!/bin/env python

# common config and methods for utils related to keeping and using certificate DN in LDAP 

import ConfigParser
import ldap

class LdapUtil:

    def __init__(self, configfile, bind=True):
        config = ConfigParser.SafeConfigParser({
            'objectclass': 'voPerson',
            'uid_attr': 'uid',
            'subj_attr':  'voPersonCertificateDN',
            'ldap_uri': 'localhost'
        })

        config.read(configfile)

        self.ldap_uri = config.get('server', 'ldap_uri')
        self.ldap_binddn = config.get('server', 'ldap_binddn')
        self.ldap_bindpw = config.get('server', 'ldap_bindpw')
        self.ldap_basedn = config.get('server', 'ldap_basedn')

        self.objectclass = config.get('schema', 'objectclass')
        self.uid_attr = config.get('schema', 'uid_attr')
        self.subj_attr = config.get('schema','subj_attr')

        self.ldap = ldap.initialize(self.ldap_uri)
        if bind:
            self.ldap.bind(self.ldap_binddn,self.ldap_bindpw)


    # pass uid * to get all subject DN attributes
    def get_certs(self,uid):
        return self.ldap.search_s(self.ldap_basedn,
                                ldap.SCOPE_SUBTREE,
                                '({0}={1})'.format(self.uid_attr,uid), 
                                [self.uid_attr,self.subj_attr])

    def rm_cert(self,dn,subject):
        self.ldap.modify_s(dn, [(ldap.MOD_DELETE, 
                            self.subj_attr,
                            subject)])

    def add_cert(self,dn,subject):
        self.ldap.modify_s(dn, [(ldap.MOD_ADD, 
                            self.subj_attr,
                            subject)])


