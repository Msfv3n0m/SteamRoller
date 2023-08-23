![](https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Ftse2.mm.bing.net%2Fth%3Fid%3DOIP.B6SgSO125PQvo3JQIIq8jQHaFP%26pid%3DApi&f=1&ipt=824c37a1645f5f6d265bdbd9f5e18d7e1fca279f297ec95283036cc4f84b8a9b&ipo=images)
# SteamRoller
This project is made for the purpose of automating basic security configurations across an Active Directory environment. It is made of several moving parts to accomplish the following:

1. Normalize a secure base configuration
2. Modular installations of reliable service settings
3. Mass-distribution of system administration tools
4. Domain-wide password changes for local and domain users

SteamRoller **DOES NOT INCLUDE ANY EXTERNAL TOOLS**. Because of this, it will internally attempt to find and import popular system administration tools such as the [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), [Process Hacker](https://sourceforge.net/projects/processhacker/), [BlueSpawn](https://github.com/ION28/BLUESPAWN), and [Hollows_Hunter](https://github.com/hasherezade/hollows_hunter). It does require Sysinternals to be at least downloaded in order for this program to run properly. </br>


For more information, visit the [wiki](https://github.com/Msfv3n0m/SteamRoller/wiki)


## Table of Contents
- [SteamRoller](#steamroller)
  - [Table of Contents](#table-of-contents)
  - [Usage](#usage)
  - [Process Description](#process-description)

  - [Future Development](#future-development)
    - [ADDS (LDAP)](#adds-ldap-1)
    - [General](#general-1)
    - [Tools](#tools-1)

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


![](https://github.com/Msfv3n0m/SteamRoller/blob/main/SteamRoller.png)




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
- General, NoPowerShellLogging, and WinRM GPOs are applied to all CLIENT computers in the domain to allow for the next step to occur securely
- PSRemoting is used to change the passwords for local users on each CLIENT computer in the domain. The new credentials are compiled into the C:\incred.csv file on the domain controller in plaintext.
  - This method does not store the domain administrator credentials in memory on the client computers because the login is of type 3 (credentials are only stored on type 2 logins)
  - PowerShell logging is disabled via GPO to prevent logs showing the users and their new passwords
  - The passwords are randomly generated and stored in a variable to prevent the password from showing up in PowerShell history
  - The password-holding-variable is set to null after each pass
  - PSExec encrypts network traffic to prevent network peers from sniffing the newly assigned passwords
- Remove unnecessary GPO Links to clean up the Group Policy Management Consoles
- Stop the SMB Share to narrow the attack surface of the server
- Automatically and remotely update the group policy configuration on domain clients 
- Securely delete the program so that it cannot be used with malintent

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
