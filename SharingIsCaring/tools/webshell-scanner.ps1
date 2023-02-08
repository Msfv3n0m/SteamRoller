$directory = "C:\inetpub\wwwroot"
gci $directory -r -af |?{gc $_.fullname | sls -patt "cmd|base64|exec|passthru|shell"} > webshells.txts