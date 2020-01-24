#!/usr/bin/env python3

# Description:
#     This module will search AD objects via a DC using a user-specified LDAP filter

from __future__ import division
from __future__ import print_function
import logging
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection

class SearchLDAP:

    def __init__(self, username, password, domain, dc, print_attribute, search_filter="(objectClass=computer)"):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__searchFilter = search_filter
        self.__print_attribute = print_attribute
        self.__lmhash = ''
        self.__nthash = ''
        self.__dc = dc
        # Create the baseDN
        domainParts = self.__domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += f'dc={i},'
        # Remove last ','
        self.baseDN = self.baseDN[:-1]
        # We can't set the KDC to a custom IP when requesting things cross-domain
        # because then the KDC host will be used for both
        # the initial and the referral ticket, which breaks stuff.

    def run(self):
        target = self.__dc

        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % target, self.baseDN, self.__dc)
            ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % target, self.baseDN, self.__dc)
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                raise

        try:
            resp = ldapConnection.search(searchFilter=self.__searchFilter,
                                         attributes=[],
                                         sizeLimit=999)
        except ldap.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
                pass
            else:
                raise

        logging.debug('Total of records returned %d' % len(resp))

        attributes = []
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == self.__print_attribute:
                        attributes.append(attribute['vals'][0])

            except Exception as e:
                logging.error('Skipping item, cannot process due to error %s' % str(e))
                pass

        return attributes

# Process command-line arguments.
if __name__ == '__main__':
    try:
        user = 'admin'
        password = ''
        domain = 'lab.local'
        dc = '172.30.23.100'
        search_filter = "(servicePrincipalName=*exchange*)"
        attribute = "dNSHostName"
        executer = SearchLDAP(user, password, domain, dc, attribute, search_filter=search_filter)
        attributes = executer.run()
        print(attributes)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))


