# Password Attack Lab - Medium

Examine the second target and submit the contents of flag.txt in /root/ as the answer.

- conducting preliminary recon on the target `nmap -Pn -sV --script=banner 10.129.x.x`
- Discovered services ssh, smb
- Initiating brute force attack on smb service using resources provided

`crackmapexec smb 10.129.x.x -L user.list -P password.list`
Result - john:123456

- Using john to enumerate the smb drive. Discovered usable drive SHAREDRIVE. using `smbclient -L //10.129.x.x/ -U john%123456`
- Further inspection using `smbclient //10.129.x.x/SHAREDRIVE -U john%123456`
- discovered a zip file `Docs.zip`. Downloading the file.
- Upon interaction with the file discovered that the file is encrypted.
- Extracting of the hash using `zip2john Docs.zip > doc.hash`
- Conducting brute force on the hash using resources. Password cracked `Destiny2022!`
- Extracting and cracking the hash for the document extracted. Discovery of pass `987654321`
- Discovered services mysql with credentials `jason:C4mNKjAtL2dydsYa6`
- Connection success to target using ssh using credentials `jason:C4mNKjAtL2dydsYa6`
- Connection success to mysql client on target.
- Discovered table cred under users database
- Discovered credentials for `dennis:7AUgWWQEiMPdqx`
- Conducting Lateral Movement in the host using the credentials `dennis:7AUgWWQEiMPdqx`
- Checking bash history. Discovered creation of ssh keys
- checking .ssh directory.
- Downloaded id_rsa
- Extracting and cracking the id_rsa hash discovered pass `P@ssw0rd12020!`
- using the discovered creds to log into the victim machine as root. Result successfull
