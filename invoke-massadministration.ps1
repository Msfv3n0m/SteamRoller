<#
.Synopsis
   Execute command on the entire domain
.DESCRIPTION
   Uses the servers.txt output from driver.ps1 to keep track of hosts to PSRemote into
.EXAMPLE
   & invoke-massadministration.ps1 "hostname"
.INPUTS
   Command to be run
.OUTPUTS
   Results from hosts
.NOTES
   File	Name	: invoke-massadministration.ps1
   Author	    : Msfv3n0m
.LINK
   https://github.com/Msfv3n0m/SteamRoller/invoke-massadministration.ps1
#>

# Params
Param (
    [String]$cmd        # command to be executed
)

function GetServers () {

}
function RunCommand ($ServersList, $cmd) {
    $ServersList | %{
        Write-Host "Attempting to change passwords on $_" -ForegroundColor Green 
        Try {
            Invoke-Command -ComputerName $_ -ScriptBlock {
                $cmd
            } 
        }
        Catch {
                Write-Output "Could not access " $_
            }
    }
}
function Netstat()
{
   $Netstat = (Netstat -ano | Select -skip 2) -Join "`n" -Split "(?= [TU][CD]P\s+(?:\d+\.|\[\w*:\w*:))" | 
       % {$_.trim() -Replace "`n",' ' -Replace '\s{2,20}',','} |
       ConvertFrom-Csv
   $Netstat  | Add-Member -MemberType NoteProperty -Name Path -Value ""
   $Netstat | %{$_.Path = $(ps -id $_.pid | Select -ExpandProperty path)}
   $Netstat| ?{$_.Path -ne $null} | ft -Autosize -Wrap
}
function ChangeAdminPass () {
    Write-Host "Setting a new administrator password" -ForegroundColor Yellow
    $newPass Read-Host "Please set a new password for $(whoami):" -AsSecureString
    Set-ADAccountPassword -Identity $env:username -NewPassword $newPass -Reset
}

# Main
# Vars
$ServersList = Get-Content -Path "$(pwd)\servers.txt"
# Logic
RunCommand ($ServersList, $cmd)
