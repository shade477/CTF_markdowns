# Powershell

**!Important Modules**

- PowerShellGet
- [AdminToolbox](https://www.powershellgallery.com/packages/AdminToolbox/11.0.8)
- [ActiveDirectory](https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps)
- [Empire](https://github.com/BC-SECURITY/Empire)
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh)
- [Bloodhound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)
- Remote System Administration Tools or `Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` (lightweight)
- [Powershell scripting](https://academy.hackthebox.com/module/167/section/1630)

**CMDLETS**
| **Command** | **Description** |
|-------------|-------------|
| `Get-ChildItem` | ~ `ls` |
| `Set-Location <path>` | ~ `cd` |
| `Get-Content <path>` | ~ `cat` |
| `Get-Command` | Displays all cmdlets loaded into current session |
| `Get-Command -verb <verb like get>` | Displays all loaded cmdlets, aliases or function having the specified verb |
| `Get-Command noun <noun like windows*>` | Displays all loaded cmdlets, aliases or function having the specified noun |
| `Get-Command -Module <module_name>` | To display cmdlet specific to that module |
| `Get-Command -Module PowerShellGet` | To display all cmdlets to interact with Powershell Gallery |
| `Get-History` | Displays a history of commands used in current session |
| `r <line_number>` | To use the command at the line number in the history |
| `$($host.Name)_history.txt` or `$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine` | The file where PSReadLine records all history |
| `Get-Alias` or `gal` | To display all aliases |
| `Set-Alias -name <alias> -value <cmdlet>` | To set alias |
| `Get-Module` | To display all loaded Modules |
| `Get-Module -ListAvailable` | To display all installed but not loaded modules |
| `Import-Module <module.psd1 script>` | To load all the modules in the script |
| `Install-Module -name <module_name>` or `Find-Module -name <module_name> \| Install-Module` | To install a module |
| `$env:PSModulePath` | To display the default PS module path |
| `Get-ExecutionPolicy` | To display the permission to run scripts on host |
| `Set-ExecutionPolicy undefined` | To set the permission to run scripts on the host |
| `Set-ExecutionPolicy -scope Process` | To set Excution policy at process level to make it temporary |

**Hotkeys**
|**Key** | **Description** |
|---------|----------|
| `CTRL+R` | Searches History, Manual autofill |
| `CTRL+L` | Screen clear |
| `CTRL+ALT+SHIFT+?` | All keyboard hotkeys |
| `esc` | To clear current line |
| `↑` or `↓` | Scroll through command history |

## User and Group Management

| **Command** | **Description** |
|------------|----------|
| **Users** |
| `Get-LocalUser` | To get all the users present locally |
| `New-LocalUser -Name <username> -NoPassword` | To create local user with no password |
| `$Password = Read-Host -AsSecureString` | To create a secure string object |
| `Set-LocalUser -Name <username> -Password $Password -Description ""` | To modify user to use a password |
| **Groups** |
| `Get-LocalGroup` | To get all the groups present locally |
| `Get-LocalGroupMember -Name <group_name>` | To list all specified group members |
| `New-LocalGroup -Name "GroupName"` | To create local group (bare-minimum)
| `New-LocalGroup -Name "MyGroup" -Description "My Description" -GroupCategory Security -GroupScope Global` | To create local group detailed |
| `Add-LocalGroupMember -Group <group> -Member <username>` | To add member to local group |

## Active Directory

| `Get-ADUser -Filter *` | To list all users in the Active Directory |
| `Get-ADUser -Identity <name>` | To list details of specific user |

## Registry

| **Command** | **Description** |
|------------|----------|
| **Cmdlets** |
| `Get-Item -Path Registry::<key_path> \| Select-Object -ExpandProperty Property` | Queries the registry path and displays proerties |
| `Get-ItemProperty -Path <hive>:<key_path>` | Gets key properties |
| `New-Item -Path <hive>:<path> -Name <key_name>` | Creates a new registry key at the path
| `New-ItemProperty -Path <hive>:<key_path> -Name "<property_name>" -PropertyType <value_type> -Value "<payload_path>"` | Sets the property for a registry key |
| `Remove-ItemProperty -Path <hive>:<keyPath> -Name  "<keyName>"` | Removes a registry key |
| ``
| **REG** |
| `reg.exe query <key_path>` | Displays properties for the query |
| `REG QUERY <hive> /F "regex" /t <value_type> /S /K` |
| `/F` | Searches for the regex pattern |
| `/t` | Filters value type |
| `/S` | Searches sub directories |
| `/K` | Narrows search to only key names |
| `reg add "<RegistryKeyPath>" /v "<ValueName>" /t <DataType> /d "<Data>" /f` | Adds key to registry path |
| `/f` | Forces update without confirmation |
| `reg add "<key_path>" /v <property_name> /t <value_type> /d "<payload_path>"` | Adds property to key |

## Log Monitoring

| **Command** | **Description** |
|------------|----------|
| **wevtutil** |
| `wevtutil el` | Enumerates all logs |
| `wevtutil gl <logName>` | Display configuration information for a specific log |
| `wevtutil gli "eventName"` | Displays specific status information about the log or log file |
| `wevtutil qe <logName> /c:<no_of_events> /rd:<boolean> /f:<format>` | Display event logs of a specific event |
| `wevtutil epl <eventName> <path>` | Export logs |
| **pwsh** |
| `Get-WinEvent -ListLog *` | Lists all logs |
| `Get-WinEvent -LogName '<logName>' -MaxEvents <number> \| Select-Object -ExpandProperty Message` | Details of a specific event |
| `Get-WinEvent -FilterHashTable @{LogName='Security';ID='4625 '}` | Filtering for Logon Failures |

## Networking

|**Cmdlet**|**Description**|
|---|---|
|`Get-NetIPInterface`|Retrieve all `visible` network adapter `properties`.|
|`Get-NetIPAddress`|Retrieves the `IP configurations` of each adapter. Similar to `IPConfig`.|
|`Get-NetNeighbor`|Retrieves the `neighbor entries` from the cache. Similar to `arp -a`.|
|`Get-Netroute`|Will print the current `route table`. Similar to `IPRoute`.|
|`Set-NetAdapter`|Set basic adapter properties at the `Layer-2` level such as VLAN id, description, and MAC-Address.|
|`Set-NetIPInterface`|Modifies the `settings` of an `interface` to include DHCP status, MTU, and other metrics.|
|`New-NetIPAddress`|Creates and configures an `IP address`.|
|`Set-NetIPAddress`|Modifies the `configuration` of a network adapter.|
|`Disable-NetAdapter`|Used to `disable` network adapter interfaces.|
|`Enable-NetAdapter`|Used to turn network adapters back on and `allow` network connections.|
|`Restart-NetAdapter`|Used to restart an adapter. It can be useful to help push `changes` made to adapter `settings`.|
|`test-NetConnection`|Allows for `diagnostic` checks to be ran on a connection. It supports ping, tcp, route tracing, and more.|


#### Boxes to Pwn

- [Blue](https://www.youtube.com/watch?v=YRsfX6DW10E&t=38s)
- [Support](https://app.hackthebox.com/machines/Support)
- [Return](https://0xdf.gitlab.io/2022/05/05/htb-return.html)

#### Great Videos to Check Out

- [APT's Love PowerShell, You Should Too](https://youtu.be/GhfiNTsxqxA) from `DEFCON SafeMode` is an excellent watch for a dive into how adversaries utilize PowerShell for exploitation. Anthony and Jake do a great job of breaking down what defenses are bypassed and even show you a few tips and tricks you can utilize.
- [PowerShell For Pentesting](https://youtu.be/jU1Pz641zjM) was presented at KringleCon 2018 by Mick Douglas provides an interesting look at how you can take basic PowerShell tasks and weaponize them for Pentesting.
- [PowerShell & Under The Wire](https://youtu.be/864S16g_SQs) John Hammond goes over a cool platform called UnderTheWire, where you can practice your PowerShell Kung-Fu.