rem Set IPv6 address properly to the tunnel interface on Windows.
rem
rem Run OnionCat with additional option -e <ifup> where <ifup> is the path to
rem this batch file.
rem

c:\windows\system32\netsh interface ipv6 add address "%OCAT_IFNAME%" %OCAT_ADDRESS%/%OCAT_PREFIXLEN%

