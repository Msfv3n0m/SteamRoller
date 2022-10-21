![](https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Ftse2.mm.bing.net%2Fth%3Fid%3DOIP.B6SgSO125PQvo3JQIIq8jQHaFP%26pid%3DApi&f=1&ipt=824c37a1645f5f6d265bdbd9f5e18d7e1fca279f297ec95283036cc4f84b8a9b&ipo=images)
# SteamRoller3
This project is made for the purpose of automating basic security configurations across an Active Directory environment. This project is made of several moving parts to accomplish the following:

1. Normalize a secure base configuration
2. Modular installations of reliable services
3. Mass-distribution of system administration tools
4. Domain-wide password changes

SteamRoller3 differs from [SteamRoller2](https://github.com/Msfv3n0m/SteamRoller3) in that this version DOES NOT INCLUDE ANY EXTERNAL TOOLS. 

## Usage
```
start.bat
```
Or
```
& driver.p1
```
Launch start.bat or driver.ps1 as an administrator. This can be achieved by right clicking the program and selecting "Start as an administrator." Or you can run the program with an elevated Command Prompt / PowerShell console using the appropriate command above.

![](https://github.com/Msfv3n0m/Images/blob/main/SteamRoller1.PNG)

## Process Description
This section follows a chronological mid-level walkthrough of this project 
- All domain users' whose username is not "Administrator" will have their password changed to a random value. This value is generated on the domain controller where the program is run. The plaintext credentials are then sent to C:\incred.csv
- In the Tools GPO, there is a "replaceme1" string. That is where the hostname of the domain controller goes. The program will replace the "replaceme1" string with it's own hostname.
  - Files are coppied via GPO through SMB shares. Therefore in order for files to be distributed, two things must happen: an smb share must be started, and the hostname or ip address of the machine where source files exist must be in the GPO.
- The backup GPO in the GPO folder are imported into the Group Policy Management Console
- An organizational unit is created for each computer in the domain such that GPO can be linked and enabled in a modular fashion to fit the needs of the server/workstation
- The SMB Share is started
- The program pauses to allow a manual "gpupdate /force" on each computer in the domain
- Sysmon is installed on each member of the domain 
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
There are many misconfigurations and vulnerabilities that exist natively in Windows. The General GPO hardens Windows as a whole to prevent common exploitations and privelage escalation opportunities for malicious actors. This GPO implements rules to enforce SOME industry best practices in Windows Server 2012 and beyond.
### ADDS (LDAP)
Active Directory is a common service offered in an enterprise environments. To ensure a resistent and reliable service configuration for domain controllers, the ADDS (LDAP) GPO allows only necessary traffic in, and starts the NTDS service.
### HTTP (IIS)
HTTP is a basic protocol that is used to offer unencrypted websites - this is typically only for internal use only. To ensure that a website is not prone to accidental misconfigurations in the firewall or service status, the HTTP (IIS) GPO enables the apropriate firewall rules to allow client access to the website and starts the web publishing service in Microsoft's Internet Information Service.
### HTTPS (IIS)
HTTPS is the secure version of HTTP. The HTTPS GPO should be applied when a secure web service is running on the computers within an organizational unit. This GPO allows HTTPS traffic into the web service and regulates the status of the service.
### RDP
Remote Desktop is necessary for remote access to a Windows computer via the user interface. The RDP GPO allows RDP traffic through the firewall and makes sure the RDP service is running.
### SMB
SMB is used to share resources such as files or printers between computers. A famous exploitation of this protocol is known as Eternal Blue or MS17-010. The SMB GPO mitigates the risk associated with this vulnerability, and maintains granted access to SMB resources. 
### WinRM (unencrypted)
The unencrypted WinRM protocol allows users to remotely manage a Windows computer via the command line. The WinRM (unencrypted) GPO allows unencrypted WinRM access through the firewall and initiates the WinRM service.
### WinRM (encrypted)
The encrypted version of WinRM secures the commands and feedback between a WinRM client and server. The WinRM (encrypted) GPO allows encrypted WinRM traffic through the firewall and launches the WinRM service.
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
### Events
The Events GPO schedules tasks on domain clients. The Events GPO is responsible for installing [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) on each member of the domain.
### NoPowerShellLogging
The NoPowerShellLogging GPO disables PowerShell script block logging and PowerShell transcription.
### PowerShellLogging
The PowerShellLogging GPO enables PowerShell script block logging and PowerShell transcription.

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
- Hallows Hunter: https://github.com/hasherezade/hollows_hunter
- Microsoft's Security Compliance Toolkit: https://www.microsoft.com/en-us/download/details.aspx?id=55319
- Process Hacker: https://processhacker.sourceforge.io/
- Sysinternals Suite: https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite

## Recommended Offline Additions
- PSExec.exe in main folder
- sdelete.exe in main folder
- Sysmon.exe in SharingIsCaring folder
- all other tools in SharingIsCaring folder called tools.zip
