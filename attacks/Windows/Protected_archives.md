```shell
curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt
```

Downloads a list of all the compressed file extenstions used today

### Cracking OpenSSL Encrypted Archives

- Using `file` utility to gain more info on the matter
```shell
shade477@htb[/htb]$ ls

GZIP.gzip  rockyou.txt

shade477@htb[/htb]$ file GZIP.gzip 

GZIP.gzip: openssl enc'd data with salted password
```

- it is best to use a loop and brute force the way in.
- one liner for this task is

```shell
for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
```

### Cracking BitLocker Encrypted Drives

- Bitlocker uses `AES128` or `AES256` encryption
- Recovery key can be used to decode the drive as an alternative to the password
    - Recovery key is 48 characters long
    - `bitlocker2john` can be used to extract the hash. Results in [4 different hash](https://openwall.info/wiki/john/OpenCL-BitLocker) extraction

**Using bitlocker2john**

```shell

shade477@htb[/htb]$ bitlocker2john -i Backup.vhd > backup.hashes
shade477@htb[/htb]$ grep "bitlocker\$0" backup.hashes > backup.hash
shade477@htb[/htb]$ cat backup.hash

$bitlocker$0$16$02b329c0453b9273f2fc1b927443b5fe$1048576$12$00b0a67f961dd80103000000$60$d59f37e...SNIP...70696f7eab6b

```
**Using hashcat to Crack backup.hash**: `hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked`

## Lab

Use the cracked password of the user Kira, log in to the host, and read the Notes.zip file containing the flag. Then, submit the flag as the answer. 

- downloading the file from the victim `scp kira@10.129.202.64:/home/kira/Documents/Notes.zip .`
- inspecting the file using the `file` utility. No special encryption found like openssl
- extracting the hash using `zip2john Notes.zip > kira_notes.hash`
- using brute force to crack the hash
    - `john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt kira_notes.hash` yeilded no result
    - Using the resources provided in the section to create a mutilated wordlist `hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list`
    - `john --wordlist=mut_password.list kira_notes.hash` resulted in the discovery of the password
