# Responder

## Using Responder

In the PHP configuration file php.ini , "allow_url_include" wrapper is set to "Off" by default, indicating that
PHP does not load remote HTTP or FTP URLs to prevent remote file inclusion attacks. However, even if
allow_url_include and allow_url_fopen are set to "Off", PHP will not prevent the loading of SMB URLs.
In our case, we can misuse this functionality to steal the NTLM hash.
Now, using the example from this link we can attempt to load a SMB URL, and in that process, we can
capture the hashes from the target using Responder.

### How does Responder work?

Responder can do many different kinds of attacks, but for this scenario, it will set up a malicious SMB
server. When the target machine attempts to perform the NTLM authentication to that server, Responder
sends a challenge back for the server to encrypt with the user's password. When the server responds,
Responder will use the challenge and the encrypted response to generate the NetNTLMv2. While we can't
reverse the NetNTLMv2, we can try many different common passwords to see if any generate the same
challenge-response, and if we find one, we know that is the password. This is often referred to as hash
cracking, which we'll do with a program called John The Ripper.

To start with, if the Responder utility is not already installed on the machine, we clone the Responder
repository to our local machine.

```shell
git clone https://github.com/lgandx/Responder
```

Verify that the `Responder.conf` is set to listen for SMB requests.

With the configuration file ready, we can proceed to start Responder with python3 , passing in the interface
to listen on using the `-I` flag:

```shell
sudo python3 Responder.py -I tun0
```

The network interface can be checked by running the ifconfig command in the terminal.
In the case of Kali Linux or the HTB Pawnbox, Responder is installed by default as a system utility, thus it can
be launched just by running the command `sudo responder -I {network_interface}` .

In case, an error is raised regarding not being able to start TCP server on port 80 , it is because port 80 is
already being used by another service on the machine. This error can be circumvented by altering the
Responder.conf file to toggle off the "HTTP" entry which is listed under the "Servers to start" section.

```shell
Location of Responder.conf file -
-> for default system install : /usr/share/responder/Responder.conf
-> for github installation : /installation_directory/Responder.conf
```

Setting the "HTTP" flag to "Off" under the "Servers to start" section in the `Responder.conf` file

| **Command** | **Description** |
|----|---|
| ``