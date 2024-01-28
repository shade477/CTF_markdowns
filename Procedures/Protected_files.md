john the ripper comes with various scripts for extracting hashes
Look for the type of hash with the suffix `2john` for example `office2john`, `pdf2john`

## Lab

Use the cracked password of the user Kira and log in to the host and crack the "id_rsa" SSH key. Then, submit the password for the SSH key as the answer. 

- Using the password discovered in previous lab `L0vey0u1!` to log into kira
- Looking into directory .ssh for keys resulting in the discovery of the required private key `id_rsa`
- copying the keyfile to home directory
- switching to a different terminal
- using scp to copy the file `scp kira@10.129.x.x:/home/kira/id_rsa .`
- deleting the keyfile from the target machine home directory to cover up tracks 😉🧐
- extracting hashes using `ssh2john id_rsa > kira_ssh.hash`
- Using `john --wordlist=/usr/seclists/Passwords/Leaked-Databases/rockyou.txt`