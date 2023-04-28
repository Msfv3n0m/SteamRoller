<#
.Synopsis
   Execute command on the entire domain
.DESCRIPTION
   Finds all Windows computers in the domain and executes a command 
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

function ChangeAdminPass () {
    Write-Host "Setting a new administrator password" -ForegroundColor Yellow
    $newPass Read-Host "Please set a new password for $(whoami):" -AsSecureString
    Set-ADAccountPassword -Identity $env:username -NewPassword $newPass -Reset
}

# Main
# Vars
$root = (Get-ADRootDSE | Select -ExpandProperty RootDomainNamingContext)
$ServersList = $(Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} -SearchBase "CN=Computers,$root" | Select -ExpandProperty Name)     # used in createouanddistribute, removelinks, changelocalpasswords
# Logic
RunCommand ($ServersList, $cmd)