#!/usr/bin/env python3

from netaddr import IPNetwork, AddrFormatError
from libnmap.parser import NmapParser
from libnmap.process import NmapProcess
from src.Logger import *
import sys
import time


class Nmap:

    report = None

    def parse_hostlist(self, hostlist):
        """Parse Nmap host list"""
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
                        sys.exit()
                    else:
                        hosts.append(line)
                except (OSError, AddrFormatError):
                    print_bad('Error importing host list file. Are you sure you chose the right file?')
                    sys.exit()

        return hosts


    def nmap_status(self, nmap_proc):
        """Prints status of Nmap process"""
        i = -1
        x = -.5
        while nmap_proc.is_running():
            i += 1
            # Every 30 seconds print that Nmap is still running
            if i % 30 == 0:
                x += .5
                print_info("Nmap running: {} min".format(str(x)))

            time.sleep(1)
        if nmap_proc.rc != 0:
            print_bad(nmap_proc.stderr)
            sys.exit()


    def run_scan(self, opts, hostlist, output_file):
        """Run Nmap process"""
        # Parse host list
        scan_hosts = self.parse_hostlist(hostlist)

        # Run Nmap
        nmap_proc = NmapProcess(targets=scan_hosts, options=opts, safe_mode=False)
        nmap_proc.sudo_run_background()
        # Print Nmap status
        self.nmap_status(nmap_proc)
        self.parse_nmap_xml(output_file)


    def parse_nmap_xml(self, nmap_xml_file):
        report = NmapParser.parse_fromfile(nmap_xml_file)
        self.report = report


    def hosts_with_open_ports(self, report, ports):
        """Get list of hosts with relevant ports open"""
        nhosts = []

        for host in report.hosts:
            if host.is_up():
                for s in host.services:
                    if s.port in ports:
                        if s.state == 'open':
                            if host not in nhosts:
                                nhosts.append(host)

        return nhosts


    def nse_host_matches(self, nhosts, script_dict):
        """
        Checks for the scripts that were run and their output

        Mandatory Arguments:
        - nhosts : list of NmapHost objects
        - script_dict : dictionary of {"script_name" : "script output that we're looking to match"}
        """
        hosts = []

        for h in nhosts:
            for script_out in h.scripts_results:
                for script in script_dict:
                    if script_out['id'] == script:
                        if script_dict[script] in script_out['output']:
                            ip = h.address
                            if ip not in hosts:
                                hosts.append(ip)

        return hosts

