<#
.Synopsis
   Hardens a Windows domain
.DESCRIPTION
   Uses a series of predefined GPO and programs to secure core aspects of the Windows operating system across a domain
.EXAMPLE
   & driver.ps1
.EXAMPLE
   start.bat
.INPUTS
   None
.OUTPUTS
   C:\incred.csv with plaintext usernames and passwords for domain and local users
.NOTES
   File	Name	: driver.ps1
   Author	    : Msfv3n0m
   Requires	    : GroupPolicy, ActiveDirectory, Microsoft.PowerShell.Utility, Microsoft.PowerShell.Management, Microsoft.PowerShell.Security, Microsoft.PowerShell.LocalAccounts PowerShell modules   
.LINK
   https://github.com/Msfv3n0m/SteamRoller3
#>
function Resume () {
	$input = ""
	While ($input -ne "cont") {
	Write-Host "Type 'cont' to continue `n" -ForegroundColor Yellow
	$input = Read-Host "input"
	}
	Write-Host "`n"
}

function GetTools ($cd, $downloads) {
    Write-Host "Copying tools to SharingIsCaring folder" -ForegroundColor Green
	gci -file $downloads | ?{$_.name -like "*hollows_hunter*"} | %{Copy-Item $_.fullname $cd\SharingIsCaring\tools}
	gci -file $downloads | ?{$_.name -like "*processhacker*"} | %{Copy-Item $_.fullname $cd\SharingIsCaring\tools}
    gci -file $downloads | ?{$_.name -like "*bluespawn*"} | %{Copy-Item $_.fullname $cd\SharingIsCaring\tools}
    if (Test-Path $downloads\Sysinternals\) {
        Copy-Item $downloads\Sysinternals\sdelete.exe $cd
        Copy-Item $downloads\Sysinternals\PSExec.exe $cd\SharingIsCaring\tools
        Copy-Item $downloads\Sysinternals\sdelete.exe $cd\SharingIsCaring\tools
        Copy-Item $downloads\Sysinternals\Autoruns.exe $cd\SharingIsCaring\tools
        Copy-Item $downloads\Sysinternals\strings.exe $cd\SharingIsCaring\tools
        Copy-Item $downloads\Sysinternals\TCPView.exe $cd\SharingIsCaring\tools
        Copy-Item $downloads\Sysinternals\procexp.exe $cd\SharingIsCaring\tools
        Copy-Item $downloads\Sysinternals\Sysmon.exe $cd\SharingIsCaring
    }
	Write-Host "`nEnsure that the appropriate tools are in the .\SharingIsCaring\tools folder" -ForegroundColor Yellow
	Resume
}


function ImportGPO2 ([String]$rootdir,[switch]$formatOutput) {
    <#
    This function is a derivative of a script found in Microsoft's Security Compliance Toolkit 
    #>
    $results = New-Object System.Collections.SortedList
    Get-ChildItem -Recurse -Include backup.xml $rootdir | ForEach-Object {
        $guid = $_.Directory.Name
        $displayName = ([xml](gc $_)).GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName.InnerText
        $results.Add($displayName, $guid)
    }
    if ($formatOutput)
    {
        $results | Format-Table -AutoSize
    }
    else
    {
        $results
    }
}



function ImportGPO1 ($cd) {
<#
This function is a derivative of a script found in Microsoft's Security Compliance Toolkit 
#>
    Write-Host "Importing GPOs" -ForegroundColor Green
    $GpoMap = ImportGPO2("$cd\GPO")
    #Write-Host "Importing the following GPOs:"
    #Write-Host
    #$GpoMap.Keys | ForEach-Object { Write-Host $_ }
    #Write-Host
    #Write-Host
    $gpoDir = "$cd\GPO"
    $GpoMap.Keys | ForEach-Object {
        $key = $_
        $guid = $GpoMap[$key]
        #Write-Host ($guid + ": " + $key)
        Import-GPO -BackupId $guid -Path $gpoDir -TargetName "$key" -CreateIfNeeded | Out-Null
    }
}

function CreateOUAndDistribute () {
    Write-Host "Creating OUs and Distributing Computers" -ForegroundColor Green
    $root = (Get-ADRootDSE | Select -ExpandProperty RootDomainNamingContext)
    Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} -SearchBase "CN=Computers,$root" | %{
	$input1 = "CN=" + $_.Name + ",CN=Computers," + $root
	$input2 = "OU=" + $_.Name + "," + $root
    New-ADOrganizationalUnit -Name $_.Name -Path $root 
    Move-ADObject -Identity $input1 -TargetPath $input2
    New-GPLink -Name "Tools" -Target $input2 -LinkEnabled Yes -Enforced Yes
    New-GPLink -Name "WinRM (http)" -Target $input2 -LinkEnabled Yes -Enforced Yes
    New-GPLink -Name "General" -Target $input2 -LinkEnabled Yes -Enforced Yes
    New-GPLink -Name "Events" -Target $input2 -LinkEnabled Yes -Enforced No
    New-GPLink -Name "RDP" -Target $input2 -LinkEnabled Yes -Enforced Yes

    }
    Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} -SearchBase "OU=Domain Controllers,$root" | %{
	$input1 = "CN=" + $_.Name + ",OU=Domain Controllers," + $root
	$input2 = "OU=" + $_.Name + "," + $root
    New-ADOrganizationalUnit -Name $_.Name -Path $root 
    Move-ADObject -Identity $input1 -TargetPath $input2
    New-GPLink -Name "Tools" -Target $input2 -LinkEnabled Yes -Enforced Yes
    New-GPLink -Name "WinRM (http)" -Target $input2 -LinkEnabled Yes -Enforced Yes
    New-GPLink -Name "General" -Target $input2 -LinkEnabled Yes -Enforced Yes
    New-GPLink -Name "Events" -Target $input2 -LinkEnabled Yes -Enforced No
    New-GPLink -Name "RDP" -Target $input2 -LinkEnabled Yes -Enforced Yes
    New-GPLink -Name "SMB" -Target $input2 -LinkEnabled Yes -Enforced Yes
    New-GPLink -Name "ADDS (LDAP)" -Target $input2 -LinkEnabled Yes -Enforced Yes
    }
}

function Replace ($cd) {
    Write-Host "Inserting DC Name into GPOs" -ForegroundColor Green
    Get-ChildItem "$cd\GPO\" | %{
        $path1 = $_.FullName + "\gpreport.xml"
	if (Test-Path -Path $path1 -PathType Leaf) {
        	(Get-Content $path1) -replace "replaceme1", "$(hostname)" | Set-Content $path1
	}
        $path2 = $_.FullName + "\DomainSysvol\GPO\Machine\Preferences\Files\Files.xml"
	if (Test-Path -Path $path2 -PathType Leaf) {
        (Get-Content $path2) -replace "replaceme1", "$(hostname)" | Set-Content $path2
	}
    } 
}

function StartSMBShare ($cd) {
    Write-Host "Starting SMB Share" -ForegroundColor Green
    net share SharingIsCaring="$cd\SharingIsCaring"
    icacls.exe "$cd\SharingIsCaring" /inheritancelevel:e /grant "*S-1-5-11:(OI)(CI)(R)" #grant acess to authenticated users
}

$passFuncs = {
function ChangeLocalPasswords ($ServersList, $cd, $admin) {
  Write-Host "Changing local passwords" -ForegroundColor Green
  $newPass="Superchiapet1"
  $cmdCommand1 = @"
  for /f "skip=1" %a in ('net user') do net user %a $newPass 
"@ # > null
  $ServersList | %{
    Write-Host "Attempting to change passwords on $_" -ForegroundColor Green 
    Try {
        Invoke-Command -ComputerName $_ -ArgumentList $cmdCommand, $admin -ScriptBlock {
            Param($cmdCommand, $admin)
            Try {
                Add-Type -AssemblyName System.Web
                Get-LocalUser | ?{$_.Name -ne $admin} | %{                           
                    $pass=[System.Web.Security.Membership]::GeneratePassword(17,2)
                    Set-LocalUser -Name $_.Name -Password (ConvertTo-SecureString -AsPlainText $pass -Force)
                    Write-Output "$(hostname)\$_,$pass"
                    $pass = $Null
                }
                Write-Host "Passwords randomized on $(hostname)" -ForegroundColor Green         
            }
            Catch {
                Add-Type -AssemblyName System.Web
                Get-WMIObject -Class Win32_UserAccount | ?{$_.Name -ne $admin} | %{
                    $name = $_.Name                           
                    $pass=[System.Web.Security.Membership]::GeneratePassword(17,2)
                    net user $_.Name $pass > $Null
                    Write-Output "$(hostname)\$name,$pass"
                    $pass = $Null
                }
                wevtutil cl Microsoft-Windows-Powershell/Operational
                Write-Host "Passwords randomized on $(hostname) with wmi" -ForegroundColor Green   
            }
        } # >> C:\incred.csv 
		# & $cd\PsExec.exe \\$_ -nobanner -accepteula powershell -command "Add-Type -AssemblyName System.Web;`$c = ','; `$h=`$(hostname); Get-LocalUser | ?{`$_.Name -ne 'Administrator'} | %{`$pass=[System.Web.Security.Membership]::GeneratePassword(20,2); Set-LocalUser -Name `$_.Name -Password (ConvertTo-SecureString -AsPlainText `$pass -Force); Write-Output `$h\`$_`$c`$pass; `$pass = `$Null}" >> C:\incred.csv
	}
    Catch {
    	  Write-Output "Could not access " $_
    	}
  }
}

function ChangeADPass () {
    Write-Host "Changing Active Directory Users' Passwords" -ForegroundColor Green
    $domain = $(Get-ADDomain | Select -ExpandProperty NetBIOSName)
    Add-Type -AssemblyName System.Web
    # Write-Output "Username,Password" > C:\incred.csv
    Get-ADUser -Filter * | ?{$_.Name -ne $env:username} | %{
    $user = $_.Name
    $pass = [System.Web.Security.Membership]::GeneratePassword(17,2)
    Write-Output "$domain\$user,$pass"
    Set-ADAccountPassword -Identity $_.Name -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $pass -Force) 
    $pass = $Null
  }
}
}

function RemoveFirewallRules($ServersList, $DCList) {
    Write-Host "Blocking default inbound and outbound traffic" -ForegroundColor Green
    if ($ServersList -ne $Null)
    {
        $ServersList| %{
            Invoke-Command -ComputerName $_ -ScriptBlock {
                Try {
                    netsh advfirewall firewall set rule all new enable=no 
                }
                Catch {
                    Write-Host "Could not block default inbound and outbound traffic on $_" -ForegroundColor Red
                }
            }
        }
    }
    if ($ServersList -ne $Null)
    {
    $DCList| %{
            Invoke-Command -ComputerName $_ -ScriptBlock {
                Try {
                    netsh advfirewall firewall set rule all new enable=no 
                }
                Catch {
                    Write-Host "Could not block default inbound and outbound traffic on $_" -ForegroundColor Red
                }
            }
        }
    }
}

function RemoveLinks ($ServersList, $DCList) {
    Write-Host "Removing GPO links" -ForegroundColor Green
    $root = (Get-ADRootDSE | Select -ExpandProperty RootDomainNamingContext)
    $ServersList| %{
        $input2 = "OU=" + $_.Name + "," + $root
	    Remove-GPLink -Name "Tools" -Target $input2
        # Remove-GPLink -Name "WinRM (http)" -Target $input2 
        Remove-GPLink -Name "Events" -Target $input2
    }
    $DCList | %{
        $input2 = "OU=" + $_.Name + "," + $root
        Remove-GPLink -Name "Tools" -Target $input2
        # Remove-GPLink -Name "WinRM (http)" -Target $input2 
        Remove-GPLink -Name "Events" -Target $input2
    }
}

function ChangeAdminPass () {
    Write-Host "Setting a new administrator password" -ForegroundColor Yellow
    $newPass = Read-Host "Please set a new password for $(whoami)" -AsSecureString
    Set-ADAccountPassword -Identity $env:username -NewPassword $newPass -Reset
}

function StopSMBShare () {
    Write-Host "Deleting SMB Share" -ForegroundColor Green
  net share SharingIsCaring /del /yes
}

function DeleteDriver ($cd) {
    Write-Host "Deleting driver.ps1" -ForegroundColor Green
	& "$cd\sdelete.exe" -accepteula -p 3 "$(pwd)\driver.ps1" > $Null
}


# Main
# Variables
$root = (Get-ADRootDSE | Select -ExpandProperty RootDomainNamingContext)    # used in removelinks and createouanddistribute
$cd = $(pwd)                                                                # used in changelocalpasswords, gettools, importgpo1, deletedriver, startsmbshare, replace
$gpoDir = "$(pwd)\GPO"                                                      # used in importgpo1
$domain = $(Get-ADDomain | Select -ExpandProperty NetBIOSName)              # used in changeadpass
$downloads = "$home\Downloads"                                              # used in gettools

$root = (Get-ADRootDSE | Select -ExpandProperty RootDomainNamingContext)
$ServersList = $(Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} -SearchBase "CN=Computers,$root")     # used in createouanddistribute, removelinks, changelocalpasswords
$DCList = $(Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} -SearchBase "OU=Domain Controllers,$root")     # used in createouanddistribute, removelinks, changelocalpasswords

$ServersList | Select -ExpandProperty Name >> servers.txt
$DCList | Select -ExpandProperty Name >> servers.txt

$job1 = Start-Job -ScriptBlock {
    param($downloads)
    gci -file $downloads | ?{$_.name -like "*Sysinternals*"} | %{Expand-Archive $_.Fullname $downloads\Sysinternals -Force}
} -ArgumentList $downloads

while ($boolInput -eq $Null)
{
    $i = Read-Host "Do you want to output a file of the new passwords? (yes or no)"
    if ($i -eq "yes")
    {   
        $boolInput = $True
    }
    elseif ($i -eq "no")
    {
        $boolInput = $False
    }
    else
    {
        Write-Host "Input not accepted" -ForegroundColor Red
    }
}

if ($boolInput)
{
    $filePath = Read-Host "What is the filepath/name you want to store the passwords in? "
    $filePathAD = $filePath + "_AD.csv"
    $filePathLocal = $filePath + "_Local.csv"
    Write-Output "Username,Password" > $filePathAD
    Write-Output "Username,Password" > $filePathLocal
}

Write-Host "What is the name of an administrator present on each Windows System?" -ForegroundColor Yellow
$admin = Read-Host 

$job1 | Wait-Job
GetTools $cd $downloads
$job2 = Start-Job -ScriptBlock {
    param($cd)
    Compress-Archive $cd\SharingIsCaring\tools $cd\SharingIsCaring\tools.zip
} -ArgumentList $cd
# $job3 = Start-Job -ScriptBlock ${Function:Replace} -ArgumentList $cd
# $job3 | Wait-Job
Replace $cd
ImportGPO1 $cd
# $job4 = Start-Job -ScriptBlock ${Function:ImportGPO1} -InitializationScript $init -ArgumentList $cd
# $job4 | Wait-Job
$job5 = Start-Job -ScriptBlock ${Function:CreateOUAndDistribute}
$job6 = Start-Job -ScriptBlock ${Function:StartSMBShare} -ArgumentList $cd
$job2 | Wait-Job
$job5 | Wait-Job 
$job6 | Wait-Job 

Write-Host "`nManually upate the group policy configuration on each member in the domain" -ForegroundColor Yellow
gpupdate /force
Resume
$job7 = Start-Job -ScriptBlock {
    param($ServersList, $filePathLocal, $boolInput, $admin)
    if ($ServersList.Name -ne $Null)
    {
        $output = ChangeLocalPasswords $ServersList.Name $cd $admin
    }
    if ($boolInput)
    {
        $output | Out-File -FilePath $filePathLocal -Append
    }
    $output = $Null
} -InitializationScript $passFuncs -ArgumentList $ServersList, $filePathLocal, $boolInput, $admin
$job8 = Start-Job -ScriptBlock{
    param($filePathAD, $boolInput)
    $output = ChangeADPass
    if ($boolInput)
    {
        $output | Out-File -FilePath $filePathAD -Append
    }
    $output = $Null
} -InitializationScript $passFuncs -ArgumentList $filePathAD, $boolInput
while ($job7.State -eq 'Running')
{
    $job7output = Receive-Job $job7 
    if ($job7output) {
        Write-Host $job7output
    }
    $job8output = Receive-Job $job8
    if ($job8output) {
        Write-Host $job8output
    }
    Start-Sleep -Milliseconds 500
}
# RemoveFirewallRules $ServersList.Name $DCList.Name
RemoveLinks $ServersList $DCList
StopSMBShare
$job8 | Wait-Job
$job8output = Receive-Job $job8
if ($job8output) {
    Write-Host $job8output
}
ChangeAdminPass
Write-Host "The program has completed successfully. Now, Manually update the group policy configuration on all computers in the domain" -ForegroundColor Green
gpmc.msc
DeleteDriver $cd
gpupdate /force 