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
   Author	: Msfv3n0m
   Requires	: GroupPolicy, ActiveDirectory, Microsoft.PowerShell.Utility, Microsoft.PowerShell.Management, Microsoft.PowerShell.Security, Microsoft.PowerShell.LocalAccounts PowerShell modules   
.LINK
   https://github.com/Msfv3n0m/SteamRoller
#>

function Resume () {
	$input = ""
	While ($input -ne "cont") {
	Write-Host "Type 'cont' to continue `n" -ForegroundColor Yellow
	$input = Read-Host "input"
	}
	Write-Host "`n"
}

function GetTools () {
	$cd = $(pwd)
	$downloads = "$cd\..\..\"
	gci -file $downloads | ?{$_.name -like "*Sysinternals*"} | %{Expand-Archive $_.Fullname $downloads\Sysinternals}
	gci -file $downloads | ?{$_.name -like "*hollows_hunter*"} | %{Copy-Item $_.fullname $cd\SharingIsCaring\tools}
	gci -file $downloads | ?{$_.name -like "*processhacker*"} | %{Copy-Item $_.fullname $cd\SharingIsCaring\tools}
    gci -file $downloads | ?{$_.name -like "*bluespawn*"} | %{Copy-Item $_.fullname $cd\SharingIsCaring\tools}
    if (Test-Path $downloads\Sysinternals\) {
        Copy-Item $downloads\Sysinternals\PSExec.exe $cd
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
	Compress-Archive $cd\SharingIsCaring\tools $cd\SharingIsCaring\tools.zip
}

function ChangeADPass () {
    $domain = $(Get-ADDomain | Select -ExpandProperty NetBIOSName)
    Add-Type -AssemblyName System.Web
    Write-Output "Username,Password" > C:\incred.csv
    Get-ADUser -Filter * | ?{$_.Name -ne "Administrator"} | %{
    $user = $_.Name
    $pass = [System.Web.Security.Membership]::GeneratePassword(15,2)
    Write-Output "$domain\$user,$pass" >> C:\incred.csv
    Set-ADAccountPassword -Identity $_.Name -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $pass -Force) 
    $pass = $Null
  }
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

function ImportGPO1 () {
<#
This function is a derivative of a script found in Microsoft's Security Compliance Toolkit 
#>
    Write-Host "Importing GPOs..."
    $GpoMap = ImportGPO2("$(pwd)\GPO")
    #Write-Host "Importing the following GPOs:"
    #Write-Host
    #$GpoMap.Keys | ForEach-Object { Write-Host $_ }
    #Write-Host
    #Write-Host
    $gpoDir = "$(pwd)\GPO"
    $GpoMap.Keys | ForEach-Object {
        $key = $_
        $guid = $GpoMap[$key]
        #Write-Host ($guid + ": " + $key)
        Import-GPO -BackupId $guid -Path $gpoDir -TargetName "$key" -CreateIfNeeded | Out-Null
    }
}

function CreateOUAndDistribute () {
    $root = (Get-ADRootDSE | Select -ExpandProperty RootDomainNamingContext)
    Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} -SearchBase "CN=Computers,$root" | %{
	$input1 = "CN=" + $_.Name + ",CN=Computers," + $root
	$input2 = "OU=" + $_.Name + "," + $root
        New-ADOrganizationalUnit -Name $_.Name -Path $root 
        Move-ADObject -Identity $input1 -TargetPath $input2
        New-GPLink -Name "Tools" -Target $input2 -LinkEnabled Yes -Enforced Yes
        New-GPLink -Name "SMB" -Target $input2 -LinkEnabled Yes -Enforced Yes
        New-GPLink -Name "General" -Target $input2 -LinkEnabled Yes -Enforced Yes
        New-GPLink -Name "Events" -Target $input2 -LinkEnabled Yes -Enforced No
	New-GPLink -Name "NoPowerShellLogging" -Target $input2 -LinkEnabled Yes -Enforced Yes
    }
    Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} -SearchBase "OU=Domain Controllers,$root" | %{
	$input1 = "CN=" + $_.Name + ",OU=Domain Controllers," + $root
	$input2 = "OU=" + $_.Name + "," + $root
        New-ADOrganizationalUnit -Name $_.Name -Path $root 
        Move-ADObject -Identity $input1 -TargetPath $input2
        New-GPLink -Name "Tools" -Target $input2 -LinkEnabled Yes -Enforced Yes
        New-GPLink -Name "General" -Target $input2 -LinkEnabled Yes -Enforced Yes
        New-GPLink -Name "Events" -Target $input2 -LinkEnabled Yes -Enforced No
	New-GPLink -Name "NoPowerShellLogging" -Target $input2 -LinkEnabled Yes -Enforced Yes
    }
}

function Replace () {
    Get-ChildItem "$(pwd)\GPO\" | %{
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

function StartSMBShare () {
    net share SharingIsCaring="$(pwd)\SharingIsCaring"
    icacls.exe "$(pwd)\SharingIsCaring" /inheritancelevel:e /grant "*S-1-5-11:(OI)(CI)(R)" #grant acess to authenticated users
}

function ChangeLocalPasswords ($ServersList) {
  $cd = $(pwd)
  $ServersList | %{
    Try {
    		#& $cd\PSExec.exe \\$_ -NoBanner -AcceptEULA PowerShell -Command "Add-Type -AssemblyName System.Web;`$c=',';`$h=`$(hostname);Get-WMIObject -Class Win32_Useraccount -Computername localhost ?{ `$_.Name -ne 'Administrator' } | %{`$pass = [System.Web.Security.Membership]::GeneratePassword(15,2); `$_.SetPassword(`$pass); Write-Output `$h\`$_`$c`$pass`n; Net User `$_ `$pass > `$NULL; `$pass = `$NULL }" >> C:\incred.csv
		& $cd\PsExec.exe \\$_ -nobanner -accepteula powershell -command "Add-Type -AssemblyName System.Web;`$c = ','; `$h=`$(hostname); Get-LocalUser | ?{`$_.Name -ne 'Administrator'} | %{`$pass=[System.Web.Security.Membership]::GeneratePassword(20,2); Set-LocalUser -Name `$_.Name -Password (ConvertTo-SecureString -AsPlainText `$pass -Force); Write-Output `$h\`$_`$c`$pass; `$pass = `$Null}" >> C:\incred.csv
	}
    Catch {
    	  Write-Output "Could not access " $_
    	}
  }
}

function RemoveLinks ($ServersList) {
    $root = (Get-ADRootDSE | Select -ExpandProperty RootDomainNamingContext)
    Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} -SearchBase "CN=Computers,$root" | %{
        $input2 = "OU=" + $_.Name + "," + $root
	Remove-GPLink -Name "Tools" -Target $input2
        Remove-GPLink -Name "SMB" -Target $input2 
        Remove-GPLink -Name "Events" -Target $input2
	Remove-GPLink -Name "NoPowerShellLogging" -Target $input2
	New-GPLink -Name "PowerShellLogging" -Target $input2 -LinkEnabled Yes -Enforced Yes
    }
    Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} -SearchBase "OU=Domain Controllers,$root" | %{
        $input2 = "OU=" + $_.Name + "," + $root
        Remove-GPLink -Name "Tools" -Target $input2
        Remove-GPLink -Name "Events" -Target $input2
	Remove-GPLink -Name "NoPowerShellLogging" -Target $input2
	New-GPLink -Name "PowerShellLogging" -Target $input2 -LinkEnabled Yes -Enforced Yes
    }
}

function StopSMBShare () {
  net share SharingIsCaring /del /yes
}

function DeleteDriver () {
	& "$(pwd)\sdelete.exe" -accepteula -p 3 "$(pwd)\driver.ps1"
}

function GPUpdate ($ServersList) {
  $cd = $(pwd)
  $ServersList | %{
    Try {
		& $cd\PsExec.exe \\$_ -nobanner -accepteula cmd /c gpupdate /force
	}
    Catch {
    	  Write-Output "Could not access " $_
    	}
  }
}

GetTools
ChangeADPass
$root = (Get-ADRootDSE | Select -ExpandProperty RootDomainNamingContext)
$ServersList = $(Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} -SearchBase "CN=Computers,$root" | Select -ExpandProperty Name)
Replace 
ImportGPO1 
CreateOUAndDistribute 
StartSMBShare 
Write-Host "`nManually upate the group policy configuration on each member in the domain" -ForegroundColor Yellow
Resume
ChangeLocalPasswords $ServersList
RemoveLinks $ServersList
StopSMBShare
#GPUpdate $ServersList
Remove-GPO -Name "NoPowerShellLogging"
Write-Host "The program has completed successfully. Now, Manually update the group policy configuration on all computers in the domain" -ForegroundColor Green
DeleteDriver
