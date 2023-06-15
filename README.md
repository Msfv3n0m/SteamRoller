![](https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Ftse2.mm.bing.net%2Fth%3Fid%3DOIP.B6SgSO125PQvo3JQIIq8jQHaFP%26pid%3DApi&f=1&ipt=824c37a1645f5f6d265bdbd9f5e18d7e1fca279f297ec95283036cc4f84b8a9b&ipo=images)
# SteamRoller
This project is made for the purpose of automating basic security configurations across an Active Directory environment. It is made of several moving parts to accomplish the following:

1. Normalize a secure base configuration
2. Modular installations of reliable service settings
3. Mass-distribution of system administration tools
4. Domain-wide password changes for local and domain users

SteamRoller3 **DOES NOT INCLUDE ANY EXTERNAL TOOLS**. Because of this, it will internally attempt to find and import popular system administration tools such as the [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), [Process Hacker](https://sourceforge.net/projects/processhacker/), [BlueSpawn](https://github.com/ION28/BLUESPAWN), and [Hollows_Hunter](https://github.com/hasherezade/hollows_hunter). It does require Sysinternals to be at least downloaded in order for this program to run properly.

## Table of Contents
- [SteamRoller3](#steamroller3)
  - [Table of Contents](#table-of-contents)
  - [Usage](#usage)
  - [Process Description](#process-description)
  - [GPOs](#gpos)
    - [General](#general)
    - [ADDS (LDAP)](#adds-ldap)
    - [HTTP (IIS)](#http-iis)
    - [HTTPS (IIS)](#https-iis)
    - [RDP](#rdp)
    - [SMB](#smb)
    - [WinRM (unencrypted)](#winrm-unencrypted)
    - [WinRM (encrypted)](#winrm-encrypted)
    - [Tools](#tools)
    - [Events](#events)
    - [PowerShellLogging](#powershelllogging)
  - [Future Development](#future-development)
    - [ADDS (LDAP)](#adds-ldap-1)
    - [General](#general-1)
    - [Tools](#tools-1)
  - [References](#references)
  - [Recommended Offline Additions](#recommended-offline-additions)

<small><i><a href='http://ecotrust-canada.github.io/markdown-toc/'>Table of contents generated with markdown-toc</a></i></small>

## Usage
```
start.bat
```
Or
```
& driver.ps1
```
Launch start.bat or driver.ps1 as an administrator. This can be achieved by right clicking the program and selecting "Start as an administrator." Or you can run the program with an elevated Command Prompt / PowerShell console using the appropriate command above.

![](https://github.com/Msfv3n0m/SteamRoller3/blob/main/SteamRoller1.png)

## Process Description
This section follows a pseudo-chronological mid-level walkthrough of this project 
- The program will try to collect popular system administration tools in order that the program may function properly and that they may be distributed to all domain clients.
- All domain users' whose username is not "Administrator" will have their password changed to a random value. This value is generated on the domain controller where the program is run. The plaintext credentials are then sent to C:\incred.csv
- In the Tools GPO, there is a "replaceme1" string. That is where the hostname of the domain controller goes. The program will replace the "replaceme1" string with it's own hostname.
  - Files are coppied via GPO through SMB shares. Therefore in order for files to be distributed, two things must happen: an smb share must be started, and the hostname or ip address of the machine where source files exist must be in the GPO. This step satisfies the latter requirement
- The backup GPO in the GPO folder are imported into the Group Policy Management Console
- An organizational unit is created for each computer in the domain such that GPO can be linked and enabled in a modular fashion to fit the needs of the server/workstation
- The SMB Share is started
- The program pauses to allow a manual "gpupdate /force" on each computer in the domain
- Sysmon is installed on each member of the domain 
- General, NoPowerShellLogging, and SMB GPOs are applied to all CLIENT computers in the domain to allow for the next step to occur securely
- PSExec - a tool from Mark Russinovich's Sysinternals - is used to change the passwords for local users on each CLIENT computer in the domain. The new credentials are compiled into the C:\incred.csv file on the domain controller in plaintext.
  - This method does not store the domain administrator credentials in memory on the client computers because the login is of type 3 (credentials are only stored on type 2 logins)
  - PowerShell logging is disabled via GPO to prevent logs showing the users and their new passwords
  - The passwords are randomly generated and stored in a variable to prevent the password from showing up in PowerShell history
  - The password-holding-variable is set to null after each pass
  - PSExec encrypts network traffic to prevent network peers from sniffing the newly assigned passwords
- Remove unnecessary GPO Links to clean up the Group Policy Management Consoles
- Stop the SMB Share to narrow the attack surface of the server
- Automatically and remotely update the group policy configuration on domain clients 
- Securely delete the program so that it cannot be used with malintent

## GPOs
### General
There are many misconfigurations and vulnerabilities that exist natively in Windows. The General GPO hardens Windows as a whole to prevent common exploitations and privelage escalation opportunities for malicious actors. This GPO implements rules to enforce SOME industry best practices in Windows Server 2012 and beyond. The following are settings that are enforced in the General GPO:
| Setting | Value | Why |
| --- | :-: | --- | 
| minimum password length | 14 | short/weak passwords are an easy target for attackers |
| password must meet complexity requirements | enabled | ensure the above setting is enforced |
| store passwords using reversible encryption | disabled | if enabled, this setting would allow total domination of a compromised system | 
| audit logon events | success and failure | keeping a log of when legitimate users log onto a system allows administrators to filter for unauthorized access | 
| audit account logon events | success and failure | keeping a log of when legitimate users log onto a system allows administrators to filter for unauthorized access | 
| audit account management | success and failure | logging changes to accounts could reveal indications of compromise |
| debug programs | null | no users require this privelage and it can lead to common attacks such as mimikatz |
force shutdown from a remote system | builtin\administrators | only administrators should be able to shutdown the system remotely | 
| guest account status | disabled | the guest account is a common security risk that should be disabled |
| prevent users from installing print drivers | enabled | this setting will help prevent print nightmare (CVE-2021-34527) |
| Domain member: digitally encrypt or sign secure channel data (always) | enabled | there is no reason for ad communication from a domain member to be unencrypted |
domain member: digitally encrypt secure channel data (when possible) | enabled | there is no reason for ad communication from a domain member to be unencrypted | 
| do not display last user name | enabled | displaying this information could be dangerous to potential attackers lurking on the network | 
| number of previous logons to cache | 0 | cached logons can be ripped from memory and brute forced as an attempt at privelage escalation | 
| microsoft network client: digitally sign communication (always) | enabled | this setting will prevent attacks that abuse unenforced smb signing requirements | 
microsoft network client: digitally sign communications (if server agrees) | enabled | this setting will prevent attacks that abuse unenforced smb signing requirements | 
microsoft network client: send unencrypted passwords to third-party smb servers | disabled | passwords should always be encrypted when sent across a network |
microsoft network server: digitally sign communications (always) | enabled | there is no reason for ad communication from a domain server to be unencrypted |
microsoft network server: digitally sign communications (if client agrees) | enabled | there is no reason for ad communication from a domain server to be unencrypted |
| allow anonymous sid/name translation | disabled | this setting releases sensitive information that should only be available to authorized users | 
| do not allow anonymous enumeration of sam accounts | enabled | anonymous users should not be able to decipher sam account or shares | 
| do not allow storage of passwords and credentials for network authentication | enabled | storing credentials is poor security posture because it allows an attacker an easy privelage escalation method within an environment | 
do not store lan manager hash value on next password change | enabled | the lan manager hash uses a weak encryption algorithm and can be cracked by several tools | 
ldap client signing requirements | negotiate signing | although I would like to require signing, I will do further testing to see if that breaks the ad environment |
| allow automatic administrative logon | disabled | automatic admin logon should never be enabled |
| allow system to be shutdown without having to log on | disabled | shutting down a system is often required for attackers to ingrain methods of persistence deep into the os | 
| behavior of the elevation prompt for standard users | automatically deny elevation requests | standard users should not have access to elevated command line sessions | 
| restrict clients allowed to make remote calls to sam | administrators only | sensative information in sam accounts should only be accessed by administrators | 
| allow localsystem null session fallback | disabled | this setting will allow unauthorized access on failure | 
| domain firewall profile | block inbound, block outbound | to ensure that regular operations are allowed upon the first running of this program, outbound traffic is still allowed |
| private firewall profile | block inbound, block outbound | to ensure that regular operations are allowed upon the first running of this program, outbound traffic is still allowed |
| public firewall profile | block inbound, block outbound | to ensure that regular operations are allowed upon the first running of this program, outbound traffic is still allowed |
| core networking firewall rules | enabled | this allows each host in the domain to fully rely on GPO for firewall rules while only allowing necessary interhost communication |
| execution policy | users cannot launch cmd, powershell, or powershell_ise | corporate users should not have access to the command line interface to restrict unnecessary access to command line interfaces | 
| turn off multi-homed name resolution | enabled | this setting prevents llmnr poisoning |
| turn off smart protocol reordering | enabled | this setting prevents llmnr poisoning | 
| protect all network connections | enabled | ensures that the firewall is running |
| set group policy refresh interval for computers | enabled: 30 mins: 5 mins | ensures that all computers in the domain will automatically update GPO settings within a half hour of the update | 
| no name release on demand | 1 | this setting prevents a DOS attack and protects the NetBIOS name from easy discovery |
| smb1 | 0 | smb1 is associated with MS17-010 (eternal blue) - it is a widely known vulnerability and should not be enabled on any windows computer | 
| use logon credential | 0 | wdigest stores plaintext passwords in lsass | 
| run as ppl | 1 | enables lsa protection on restart |
| lan manager authentication level | send ntlmv2 response only/refuse ntlm & lm | ntlm and lm authentication methods are insecure; it is best practice to use ntlmv2 |
| audit process tracking | successes | this audit policy presents a more detailed view of what a user does on a system. this will benefit the detail of incident response reports | 


### ADDS (LDAP)
Active Directory is a common service offered in an enterprise environments. To ensure a resistent and reliable service configuration for domain controllers, the ADDS (LDAP) GPO allows only necessary traffic in. The following are settings that are enforced in the ADDS (LDAP) GPO:
| Setting | Value | Why |
| --- | :-: | --- | 
| default ADDS server firewall rules | enabled | these rules will be enabled at the domain level so that a domain controller's firewall rules cannot be tampered with locally |
### HTTP (IIS)
HTTP is a basic protocol that is used to offer unencrypted websites - this is typically only for internal use only. To ensure that a website is not prone to accidental misconfigurations in the firewall or service status, the HTTP (IIS) GPO enables the apropriate firewall rules to allow client access to the website. The following are settings that are enforced in the HTTP (IIS) GPO:
| Setting | Value | Why |
| --- | :-: | --- | 
| default HTTP server firewall rules | enabled | these rules will be enabled at the domain level so that a web server's  firewall rules cannot be tampered with locally |
### HTTPS (IIS)
HTTPS is the secure version of HTTP. The HTTPS GPO should be applied when a secure web service is running on the computers within an organizational unit. This GPO allows HTTPS traffic into the web service. The following are settings that are enforced in the HTTPS (IIS) GPO:
| Setting | Value | Why |
| --- | :-: | --- | 
| default HTTPS server firewall rules | enabled | these rules will be enabled at the domain level so that a web server's  firewall rules cannot be tampered with locally |
### RDP
Remote Desktop is necessary for remote access to a Windows computer via the user interface. The RDP GPO allows RDP traffic through the firewall. The following are settings that are enforced in the RDP GPO:
| Setting | Value | Why |
| --- | :-: | --- | 
| default RDP server firewall rules | enabled | these rules will be enabled at the domain level so that an RDP server's  firewall rules cannot be tampered with locally |
| do not allow clipboard redirection | disabled | the clipboard can be a useful tool for administrators and can become cumbersome if disabled |
| always prompt for password upon connection | enabled | a user should always authenticate before a session is created |
| set client connection encryption level | high level | a high level of encryption ensures that attackers cannot sniff sensitive information traveling across a network |
### SMB
SMB is used to share resources such as files or printers between computers. A famous exploitation of this protocol is known as Eternal Blue or MS17-010. The SMB GPO mitigates the risk associated with this vulnerability, and maintains granted access to SMB resources. The following are settings that are enforced in the SMB GPO:
| Setting | Value | Why |
| --- | :-: | --- | 
| subset of default SMB server firewall rules | enabled | these rules will be enabled at the domain level so that a SMB server's firewall rules cannot be tampered with locally |
### WinRM (unencrypted)
The unencrypted WinRM protocol allows users to remotely manage a Windows computer via the command line. The WinRM (unencrypted) GPO allows unencrypted WinRM access through the firewall. The following are settings that are enforced in the WinRM (unencrypted) GPO:
| Setting | Value | Why |
| --- | :-: | --- | 
| default WinRM server firewall rules | enabled | these rules will be enabled at the domain level so that a WinRM server's firewall rules cannot be tampered with locally |
| allow basic authentication | enabled | this setting will allow users to authenticate with a password |
| allow credssp authentication | disabled | credssp authentication is depricated and can lead to exposed credentials | 
| allow remote server management through winrm | enabled | if this gpo is applied to a winrm server, then winrm should be enabled |
| allow unencrypted traffic | enabled | if the winrm server does not offer encryption, the unencrypted traffic must be allowed |
| disallow winrm from storing runas credentials | enabled | storing credentials can lead to an unnecessary risk of exposing sensitive passwords | 
| allow remote shell access | enabled | this setting is required in order for winrm to function properly |

### WinRM (encrypted)
The encrypted version of WinRM secures the commands and feedback between a WinRM client and server. The WinRM (encrypted) GPO allows encrypted WinRM traffic through the firewall. The following are settings that are enforced in the WinRM (encrypted) GPO:
| Setting | Value | Why |
| --- | :-: | --- | 
| default WinRM server firewall rules | enabled | these rules will be enabled at the domain level so that a WinRM server's firewall rules cannot be tampered with locally |
| allow basic authentication | enabled | this setting will allow users to authenticate with a password |
| allow credssp authentication | disabled | credssp authentication is depricated and can lead to exposed credentials | 
| allow remote server management through winrm | enabled | if this gpo is applied to a winrm server, then winrm should be enabled |
| allow unencrypted traffic | disabled | if the winrm server offers encryption, unencrypted traffic is an unnecessary risk |
| disallow winrm from storing runas credentials | enabled | storing credentials can lead to an unnecessary risk of exposing sensitive passwords | 
| allow remote shell access | enabled | this setting is required in order for winrm to function properly |

### Tools
System administration tools are desirable to have on both corporate servers and employee workstations. The Tools GPO distributes the tools.zip file to all domain controllers and clients. You can compile any tools you want into a tools.zip file in the SharingIsCaring folder and it will be pulled down by every client in the domain. In addition to a tools.zip file, the Tools GPO will also attempt to install sysmon on all domain clients. Although Sysmon is not included in this project, it can be added to the SharingIsCaring folder. Here are some examples of programs that could be distributed in the tools.zip file via the Tools GPO:
- [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
  - [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
  - [Strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings)
  - [Procexp](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
  - [Psexec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)
  - [Sdelete](https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete)
  - [Tcpview](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview)
  - [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Process Hacker](https://processhacker.sourceforge.io/)
- [Hallows Hunter](https://github.com/hasherezade/hollows_hunter)
- [Bluespawn](https://github.com/ION28/BLUESPAWN) </br>

Here are some tools that are included in the SharingIsCaring/tools folder:
- batch pii scanner
- PowerShell webshell scanner

### Events
The Events GPO schedules tasks on domain clients. The Events GPO is responsible for installing [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) on each member of the domain.

### PowerShellLogging
The PowerShellLogging GPO enables PowerShell script block logging and PowerShell transcription. The following are settings that are enforced in the PowerShellLogging GPO:
| Setting | Value | Why |
| --- | :-: | --- | 
| turn on powershell script block logging | enabled | powershell script block logging is a great tool for incident response in finding indications of compromise on a system | 
| turn on powershell transcription | enabled | powershell transcription is a great tool for incident response in finding indications of compromise on a system | 
## Future Development
### ADDS (LDAP)
- require ldap signing

### General 
- network access: do not allow anonymous enumeration of sam accounts and shares
- admin approval mode
- minimum password length

### Tools
- change hashes of sysinternals and rename?

## References
- Microsoft's Security Compliance Toolkit: https://www.microsoft.com/en-us/download/details.aspx?id=55319
- Process Hacker: https://sourceforge.net/projects/processhacker/
- Sysinternals Suite: https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite
- Hollows_Hunter: https://github.com/hasherezade/hollows_hunter
## Recommended Offline Additions
- PSExec.exe in main folder
- sdelete.exe in main folder
- Sysmon.exe in SharingIsCaring folder
- all other tools in SharingIsCaring folder called tools.zip
