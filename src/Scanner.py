#!/usr/bin/env python3

from netaddr import IPNetwork, AddrFormatError
from libnmap.parser import NmapParser
from libnmap.process import NmapProcess


class NmapError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)

class Nmap:


    def __init__(self):

        self.report = None
        self.nmap_proc = None

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
                        raise NmapError('CIDR notation only in the host list, e.g. 10.0.0.0/24')
                    else:
                        hosts.append(line)
                except (OSError, AddrFormatError):
                    raise NmapError('Error importing host list file. Are you sure you chose the right file?')

        return hosts


    def run_scan(self, opts, hostlist):
        """
        Run Nmap process
        """
        # Parse host list
        scan_hosts = self.parse_hostlist(hostlist)

        # Run Nmap
        self.nmap_proc = NmapProcess(targets=scan_hosts, options=opts, safe_mode=False)
        self.nmap_proc.sudo_run_background()
        return self.nmap_proc


    def parse_nmap_xml(self, nmap_xml_file):
        report = NmapParser.parse_fromfile(nmap_xml_file)
        self.report = report


    def hosts_with_open_ports(self, ports):
        """
        Get list of hosts with relevant ports open
        """
        nhosts = []

        for host in self.report.hosts:
            if host.is_up():
                for s in host.services:
                    if s.port in ports:
                        if s.state == 'open':
                            if host not in nhosts:
                                nhosts.append(host)

        return nhosts


    def nse_host_matches(self, nhosts, script_match):
        """
        Checks for the scripts that were run and their output

        Mandatory Arguments:
        - nhosts : list of NmapHost objects
        - script_match : dictionary of {"script_name" : "script output that we're looking to match"}
        """
        hosts = []

        for h in nhosts:
            for script_out in h.scripts_results:
                for script in script_match:
                    if script_out['id'] == script:
                        if script_match[script] in script_out['output']:
                            ip = h.address
                            if ip not in hosts:
                                hosts.append(ip)

        return hosts

