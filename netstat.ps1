$Netstat = (Netstat -ano | Select -skip 2) |%{$_.trim() -replace "\s{2,20}",','} | convertfrom-csv
$Netstat | Add-Member -MemberType NoteProperty -Name Path -Value ""
$Netstat | %{$_.Path = $(ps -id $_.pid | Select -ExpandProperty path)}
$Netstat = $Netstat | ?{$_.Path -ne $null}
$Netstat | ft -Autosize -Wrap
