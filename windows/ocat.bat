@echo off

set ONIONURL=SET_THIS_PROPERLY

if "%ONIONURL%" == "SET_THIS_PROPERLY" (
        echo "Your have to set the variable ONIONURL within this script to a proper .onion URL."
        pause
        exit
)

set mypath=%~dp0
cd %mypath:~0,-1%

ocat.exe -e ocat-ifup.bat %ONIONURL%

