#!/usr/bin/env python3

# Description:
#     This module will search AD objects via a DC using a user-specified LDAP filter

from __future__ import division
from __future__ import print_function
import logging
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection

class SearchLDAP:

    def __init__(self, username, password, user_domain, target_domain, printAttribute, searchFilter="(objectClass=computer)",
                 kdcHost=None, doKerberos=False, aesKey=None, hashes=None):
        self.__username = username
        self.__password = password
        self.__domain = user_domain
        self.__targetDomain = target_domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__searchFilter = searchFilter
        self.__printAttribute = printAttribute
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')
        # Create the baseDN
        domainParts = self.__targetDomain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += f'dc={i},'
        # Remove last ','
        self.baseDN = self.baseDN[:-1]
        # We can't set the KDC to a custom IP when requesting things cross-domain
        # because then the KDC host will be used for both
        # the initial and the referral ticket, which breaks stuff.
        if user_domain != target_domain and self.__kdcHost:
            logging.warning('DC ip will be ignored because of cross-domain targeting.')
            self.__kdcHost = None

    def getMachineName(self):
        if self.__kdcHost is not None and self.__targetDomain == self.__domain:
            s = SMBConnection(self.__kdcHost, self.__kdcHost)
        else:
            s = SMBConnection(self.__targetDomain, self.__targetDomain)
        try:
            s.login('', '')
        except Exception:
            if s.getServerName() == '':
                raise 'Error while anonymous logging into %s'
        else:
            try:
                s.logoff()
            except Exception:
                # We don't care about exceptions here as we already have the required
                # information. This also works around the current SMB3 bug
                pass
        return "%s.%s" % (s.getServerName(), s.getServerDNSDomainName())

    def run(self):
        if self.__doKerberos:
            target = self.getMachineName()
        else:
            if self.__kdcHost is not None and self.__targetDomain == self.__domain:
                target = self.__kdcHost
            else:
                target = self.__targetDomain

        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % target, self.baseDN, self.__kdcHost)
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcHost)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % target, self.baseDN, self.__kdcHost)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcHost)
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

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == self.__printAttribute:
                        print(attribute['vals'][0])

            except Exception as e:
                logging.error('Skipping item, cannot process due to error %s' % str(e))
                pass


# Process command-line arguments.
if __name__ == '__main__':
    try:
        user = 'admin'
        passwd = ''
        userDomain = 'lab.local'
        targetDomain = 'lab.local'
        kdcHost = '172.30.23.100'
        searchFilter = "(servicePrincipalName=*WIN*)"
        attribute = "dNSHostName"
        executer = SearchLDAP(user, passwd, userDomain, targetDomain, attribute, kdcHost=kdcHost, searchFilter=searchFilter)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))


