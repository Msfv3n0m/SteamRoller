@echo off
rem cant scan doc/docx/xls/xlsx files
GOTO :Main
rem ***scan folder for pii***
:scanFolder
    FOR /r %~1\ %%f IN (*.txt, *.csv, *.doc, *.docx, *.xlsx, *.xls) DO (
        IF %%f == *.txt OR IF %%f == *.csv (
            findstr /i "fname lname ssn email birthday dob address" "%%f">NUL && echo %%f >> %~2
        )
    ) ELSE (
        echo %%f >> %~2
    )
    exit /B 0
rem ***Main function***
:Main
set logFile="pii_locations.txt"
set folder1="C:\Users\"
set folder2="C:\inetpub\"
set folder3="C:\xampp\"
set folder4=C:\ProgramData\"
IF exist %folder1% (call :scanFolder %folder1%, %logFile%)
IF exist %folder2% (call :scanFolder %folder2%, %logFile%)
IF exist %folder3% (call :scanFolder %folder3%, %logFile%)
IF exist %folder4% (call :scanFolder %folder4%, %logFile%)
