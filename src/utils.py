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


def get_local_ip(iface):
    """
    Gets the the local IP of an interface
    """
    ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    return ip


def follow_file(thefile):
    """
    Works like tail -f
    Follows a constantly updating file
    """
    thefile.seek(0,2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line


def print_bad(msg):
    print(colored('[-] ', 'red') + msg)


def print_info(msg):
    print(colored('[*] ', 'blue') + msg)


def print_good(msg):
    print(colored('[+] ', 'green') + msg)


def print_great(msg):
    print(colored('[!] {}'.format(msg), 'yellow', attrs=['bold']))