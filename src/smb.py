from impacket.smbconnection import SMBConnection
from impacket.smb import SMB_DIALECT
import concurrent.futures
import asyncio

def get_smb_signing(host, port):
    """
    Check if SMB signing is required
    """
    try: # SMBv1/2
        conn = SMBConnection(host, host, None, port, preferredDialect=SMB_DIALECT, timeout=10)
        if not conn.isSigningRequired(): # Signing not required
            return host
    except Exception as e:
        try: #SMBv3
            conn = SMBConnection(host, host, None, port, timeout=10)
            if not conn.isSigningRequired():
                return host
        except Exception as e:
            print(str(e))
            return

async def get_unsigned_hosts(loop, hosts):
    """
    Returns list of hosts without SMB signing
    """
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=128)
    done, pending = await asyncio.wait(
        fs=[loop.run_in_executor(executor, get_smb_signing, host, 445) for host in hosts],
        return_when=asyncio.ALL_COMPLETED
    )
    hosts = list(filter(None, ([task.result() for task in done]))) # Filter None from list
    write_unsigned_hosts(hosts)
    return hosts

def write_unsigned_hosts(hosts):
    if len(hosts) > 0:
        old_lines = None
        filename = 'unsigned-smb-hosts.txt'
        if os.path.isfile(filename):
            f = open(filename, 'r')
            old_lines = f.readlines()
            f.close()

        for host in hosts:
            host = host + '\n'
            if old_lines:
                if host not in old_lines:
                    with open(filename, 'a+') as f:
                        f.write(data)
            else:
                with open(filename, 'a+') as f:
                    f.write(data)