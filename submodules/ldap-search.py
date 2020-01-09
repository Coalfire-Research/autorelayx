#!/usr/bin/env python3
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#  Alberto Solino (@agsolino)
#
# Description:
#     This module will try to find Service Principal Names that are associated with normal user account.
#     Since normal account's password tend to be shorter than machine accounts, and knowing that a TGS request
#     will encrypt the ticket with the account the SPN is running under, this could be used for an offline
#     bruteforcing attack of the SPNs account NTLM hash if we can gather valid TGS for those SPNs.
#     This is part of the kerberoast attack researched by Tim Medin (@timmedin) and detailed at
#     https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf
#
#     Original idea of implementing this in Python belongs to @skelsec and his
#     https://github.com/skelsec/PyKerberoast project
#
#     This module provides a Python implementation for this attack, adding also the ability to PtH/Ticket/Key.
#     Also, disabled accounts won't be shown.
#
from __future__ import division
from __future__ import print_function
import logging
from datetime import datetime
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection
from IPython import embed

class SearchLDAP:
    @staticmethod
    def printTable(items, header):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(row[i]) for row in items])
            colLen.append(max(rowMaxLen, len(col)))

        outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])

        # Print header
        print(outputFormat.format(*header))
        print('  '.join(['-' * itemLen for itemLen in colLen]))

        # And now the rows
        for row in items:
            print(outputFormat.format(*row))

    def __init__(self, username, password, user_domain, target_domain, searchFilter="(objectClass=computer)",
                 kdcHost=False, doKerberos=False, aesKey=None, hashes=None):
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
            print(target, self.baseDN, self.__kdcHost)
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

        answers = []
        logging.debug('Total of records returned %d' % len(resp))

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'servicePrincipalName':
                        print(attribute['vals'][0])
                    if str(attribute['type']) == 'dNSHostName':
                        print(attribute['vals'][0])

            except Exception as e:
                logging.error('Skipping item, cannot process due to error %s' % str(e))
                pass

        if len(answers)>0:
            self.printTable(answers, header=[ "ServicePrincipalName", "Name", "MemberOf", "PasswordLastSet", "LastLogon"])
            print('\n\n')

        else:
            print("No entries found!")


# Process command-line arguments.
if __name__ == '__main__':
    try:
        user = 'admin'
        passwd = 'P@ssw0rd'
        userDomain = 'lab.local'
        targetDomain = 'lab.local'
        kdcHost = '172.30.23.100'
        searchFilter = "(servicePrincipalName=*WIN*)"
        executer = SearchLDAP(user, passwd, userDomain, targetDomain, kdcHost=kdcHost, searchFilter=searchFilter)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))


