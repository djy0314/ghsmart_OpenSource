@echo off
title ghsmart Emergency Network Repair
rem ============================================================
rem  ghsmart Emergency Network Repair (v1.0.2)
rem  Use this if: ghsmart is frozen / network is broken after
rem  force-killing ghsmart / company sites unreachable.
rem  What it does:
rem    1) Turn OFF system proxy  (ProxyEnable = 0)
rem    2) Flush DNS cache
rem    3) Ask Windows to reload proxy settings (best effort)
rem  Note: this script NEVER touches anything else.
rem ============================================================
echo.
echo  ==============================================
echo   ghsmart Emergency Network Repair
echo   ghsmart wang luo ji jiu / network rescue
echo  ==============================================
echo.

echo  [step 1/3] Current proxy setting:
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer 2>nul | findstr /i "ProxyServer"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable 2>nul | findstr /i "ProxyEnable"
echo.

echo  [step 2/3] Turning OFF system proxy (ProxyEnable=0) ...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1
if errorlevel 1 (
    echo      FAILED to write registry. Right-click this file
    echo      and choose "Run as administrator", then retry.
) else (
    echo      OK. System proxy is now OFF - direct connection.
)

echo  [step 3/3] Flushing DNS cache ...
ipconfig /flushdns >nul 2>&1
echo      OK.

echo  [extra] Asking Windows to reload proxy settings ...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$q=[char]34; $d='[DllImport('+[char]34+'wininet.dll'+[char]34+',SetLastError=true)]public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l);'; try { $t=Add-Type -MemberDefinition $d -Name W -Namespace N -PassThru; $t::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0)|Out-Null; $t::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)|Out-Null; 'OK' } catch { 'SKIP' }" 2>nul
echo      Done.

echo.
echo  ==============================================
echo   All done. Network should be back to DIRECT.
echo   If your browser still cannot open pages:
echo     - fully close and reopen the browser, or
echo     - restart the computer.
echo   ghsmart will also auto-clean stale proxy
echo   on its next startup.
echo  ==============================================
echo.
pause
