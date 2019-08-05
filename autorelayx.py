#!/usr/bin/env python3

import argparse
import math
from src.Logger import *
from src.Scanner import Nmap
import time
import os
import sys


def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--hostlist", help="Host list file")
    parser.add_argument("-x", "--xml", help="Nmap XML file")
    parser.add_argument("-i", "--interface", help="Interface to use with Responder")
    parser.add_argument("-c", "--command", help="Remote command to run upon successful NTLM relay")
    parser.add_argument("-6", "--mitm6", action='store_true', help="Run mitm6 in conjunction with the relay attack")
    #parser.add_argument("-p", "--privexchange", action='store_true', help="Remote command to run upon successful NTLM relay")
    return parser.parse_args()


def get_nmap_report(ports):
    """Run and parse Nmap output"""
    nmap = Nmap()

    if args.xml:
        nmap.parse_nmap_xml(args.xml)
    else:
        str_ports = ','.join(str(p) for p in ports)
        output_file = f'/tmp/autorelayx-{math.floor(time.time())}'
        opts = f'-sSV -n --max-retries 5 -T4 -p {str_ports} --script smb-security-mode,smb2-security-mode -oA {output_file}'
        nmap.run_scan(opts, args.hostlist, output_file + '.xml')

    return nmap


def get_smb_hosts(nmap, ports):
    nhosts = nmap.hosts_with_open_ports(nmap.report, ports)
    if len(nhosts) == 0:
        print_bad('No hosts with relevant ports open')
        sys.exit()
    else:
        print_info('Hosts with SMB ports open:')
        for h in nhosts:
            print_good('  ' + h.address)

    return nhosts


def print_smb_unsigned_hosts(smb_unsigned_hosts):
    """Prints hosts without SMB signing"""
    print_info('Hosts without SMB signing:')
    for h in smb_unsigned_hosts:
        print_good('  ' + h)


def run_and_parse_nmap():
    """Runs Nmap or parses Nmap output"""
    ports = [139, 445]
    nmap = get_nmap_report(ports)
    nhosts = get_smb_hosts(nmap, ports)
    script_dict = {'smb-security-mode':'message_signing: disabled', 'smb2-security-mode':'not required'}
    smb_unsigned_hosts = nmap.nse_host_matches(nhosts, script_dict)
    print_smb_unsigned_hosts(smb_unsigned_hosts)
    return nmap

def main():
    nmap = run_and_parse_nmap()


if __name__ == "__main__":
    args = parse_args()

    if os.geteuid():
        print_bad('Run as root')
        sys.exit()

    main()
