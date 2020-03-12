from src.utils import *
import re
from autorelayx import parse_args

def test_get_iface():
    iface = get_iface()
    assert type(iface) is str
    assert len(iface) < 20


def test_get_iface_and_ip():
    iface = get_iface()
    ip = get_local_ip(iface)
    regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''
    assert type(ip) is str
    assert re.search(regex, ip)


def test_parse_creds():
    args = parse_args(['-u SOMETHING/username:P/:ss/:w0rd'])
    dom, user, pw = parse_creds(args)
    assert dom == "SOMETHING"
    assert user == "username"
    assert pw == "P/:ss/:w0rd"
