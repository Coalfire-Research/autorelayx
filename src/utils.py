#!/usr/bin/env python3

import netifaces
from termcolor import colored
import time

def get_iface():
    """
    Gets the right interface for Responder
    """
    try:
        iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    except:
        ifaces = []
        for iface in netifaces.interfaces():
            # list of ipv4 addrinfo dicts
            ipv4s = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])

            for entry in ipv4s:
                addr = entry.get('addr')
                if not addr:
                    continue
                if not (iface.startswith('lo') or addr.startswith('127.')):
                    ifaces.append(iface)

        iface = ifaces[0]

    return iface

def get_iface_and_ip(args):
    if not args.interface:
        iface = get_iface()
    else:
        iface = args.interface

    local_ip = get_local_ip(iface)

    return iface, local_ip

def parse_creds(creds):
    if ':' in creds:
        colon_split = creds.split(':', 1) # dom/user, pass
        password = colon_split[1]
        creds = colon_split[0]
    else:
        password = ''

    if '/' in creds:
        slash_split = creds.split("/", 1)
        dom = slash_split[0].strip()
        user = slash_split[1].strip()
    else:
        dom = ''
        user = creds

    return dom, user, password

def get_local_ip(iface):
    """
    Gets the the local IP of an interface
    """
    ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    return ip

def print_bad(msg):
    print(colored('[-] ', 'red') + msg)


def print_info(msg):
    print(colored('[*] ', 'blue') + msg)


def print_good(msg):
    print(colored('[+] ', 'green') + msg)


def print_great(msg):
    print(colored('[!] {}'.format(msg), 'yellow', attrs=['bold']))