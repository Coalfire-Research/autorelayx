#!/usr/bin/env python3

from src.process import Program

class Responder(Program):

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd

    def edit_resp_conf(self, switch, protocols, conf):
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
            # Make sure the change we're making is necessary
            if re.search(p + ' = ' + opp_switch, filedata):
                filedata = filedata.replace(p + ' = ' + opp_switch, p + ' = ' + switch)
        with open(conf, 'w') as f:
            f.write(filedata)