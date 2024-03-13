# local
notepad tmp | out-null 
add-type -AssemblyName system.web 
glu | ?{$_.name -notin (gc tmp.txt)} | %{
    $pass = [system.web.security.membership]::GeneratePassword(17,2)
    set-localuser -name $_.name -password (convertto-securestring -AsPlainText $pass -force)
    $pass = $Null
}
del tmp.txt

# domain
<#
notepad tmp | out-null
$domain = $(Get-ADDomain | Select -ExpandProperty NetBIOSName)
Add-Type -AssemblyName System.Web
Get-ADUser -Filter * | ?{$_.name -notin (gc tmp.txt)} | %{
    $user = $_.SAMAccountName
    $pass = [System.Web.Security.Membership]::GeneratePassword(17,2)
    $pass = $pass.replace(',','!')
    $pass = $pass.replace(';','?')
    Set-ADAccountPassword -Identity $_.SAMAccountName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $pass -Force) 
    $pass = $Null
}
del tmp.txt
#>