## Stuff to look for
| Files         | History              | Memory               | Key-Rings                  |
|---------------|:--------------------:|:--------------------:|:--------------------------:|
| Configs       | Logs                 | Cache                | Browser stored credentials |
| Databases     | Command-line History | In-memory Processing |                            |
| Notes         |                      |                      |                            |
| Scripts       |                      |                      |                            |                     
| Source codes  |                      |                      |                            |
| Cronjobs      |                      |                      |                            |
| SSH Keys      |                      |                      |                            |

------------------

| Tables        | Are           | Memory                 | Key-Rings                  |
| ------------- |:-------------:| ----------------------:| --------------------------:|
| col 3 is      | right-aligned |   Cache                | Browser stored credentials |
| col 2 is      | centered      |   In-memory Processing |                            |
| zebra stripes | are neat      |                        |                            |

---

| Syntax | Description |
| ----------- | ----------- |
| Header | Title |
| Paragraph | Text |


## Search one liners

| **Command** | **Description** |
|-------------|-----------------|
| `$ for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null \| grep -v "lib\|fonts\|share\|core" ;done` | This is used to list all different types of configuration files |
| `$ for i in $(find / -name *.cnf 2>/dev/null \| grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null \| grep -v "\#";done` | Looks for credentials within those config files |
| `$ for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null \| grep -v "doc\|lib\|headers\|share\|man";done` | looks for db files |
| `find /home/* -type f -name "*.txt" -o ! -name "*.*"` | looks for files with `.txt` and files with no extentions |
| `$ for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null \| grep -v "doc\|lib\|headers\|share";done` | Looks for scripts |
| `$ for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done` | Looks for logs |

> LaZagne also works

## Useful password locations
| **path** | **Contents** |
|----------|--------------|
| `/usr/lib/x86_x64-linux-gnu/security/` | May contain `pam_unix.so`, `pam_unix2.so` |
| `/etc/passwd` | File contains info on every user on the system |
| `/etc/shadow` | File contains all encrypted hashes |

### passwd file entry format

login_name:Password_info:UID:GUID:Full_name/comments:home_dir:shell
example:
cry0l1t3:x:1000:1000:cry0l1t3,,,:/home/cry0l1t3:/bin/bash

> **Tip** If the passwd file is writeable then removing the password_info value it will allow login without password.

TUqr7QfLTLhruhVbCP
