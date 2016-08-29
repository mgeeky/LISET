@echo off
SetLocal EnableExtensions EnableDelayedExpansion

SET VERSION=0.5

echo.
echo                 SystemSnapshot v%VERSION%
echo IT Forensics and System incident data collection tool. 
echo Mariusz B. / MGeeky, 2011-2016
echo.

REM This script collects information about system from different
REM locations. It gathers:
REM  x - not implemented yet
REM  s - skipped
REM  c - conditional (long steps)
REM  d - disabled code
REM
REM d 0a. Full memory dump
REM 0b. Preliminary system informations gathering
REM 1. Collecting some forensics traces
REM 2. Tree view of SS_PATHs
REM 3. DIR view of SS_PATHs
REM 4. Whole list of running (and not) services
REM 5. Whole list of running (and not) drivers
REM 6. WMI database queries.
REM 7. List of running/loaded/unloaded DLLs
REM 8. Current PROCESS List (from 3 different collectors):
REM 	 * system tasklist
REM		 * WMI database
REM 	 * Sysinternals PSLIST
REM  	 * and any extra source
REM s 9. MD5 sums of each file in SS_PATHs
REM s 10. Dump of actual machine memory (win32dd)
REM s 11. Dump of actual kernel memory (Crash Dump)
REM 12. Complete log from netstat
REM 13. DNS Cache list (ipconfig /flushdns )
REM 14. ARP Routing Table
REM 15. XueTr/PCHunter logs gathering
REM 16. Simple autorun values list (simple view format)
REM s 17. Copy of Master Boot Record
REM 18. Whole system registered Handles list
REM x 19. Every drive NTFS info
REM 20. Open ports list (through TCPVcon.exe)
REM 21. Current logged in users list
REM 22. Simple copy of hosts file
REM 23. Possible FIREWALL filters (netsh)
REM 24. Complete SYSTEMINFO log
REM c 25. List of every spotted Alternate Data Stream in SS_PATHs
REM c 26.  Dump of registry Keys (Exports)
REM c 27. Sigcheck recursive files scanning
REM
REM Then script will move all gathered log files into one folder
REM and pack this folder (zip or something) and compare MD5 checksums


REM SystemSnapshot paths to scan while collecting files lists
set SS_PATH1=%SystemRoot%
set SS_PATH2=%UserProfile%
set SS_PATH3=%ProgramFiles%

REM Directories where neccessery tools are placed
SET cwd=%~dp0
SET TOOLSDIR=%cwd%tools

REM SystemSnapshot paths counter
set LOGDIR=%cd%\Logs_%COMPUTERNAME%_%RANDOM%
set PERFORM_ALL=0

:: Setting processor architecture
set ARCH=86

for /f "tokens=3,* delims= " %%i in ('reg query "HKLM\System\CurrentControlSet\Control\Session Manager\Environment" /v PROCESSOR_ARCHITECTURE') do set ARCH=%%i

if "%ARCH%" == "x86" (
    set ARCH=86
) else (
    set ARCH=64
)

set xuetr=%TOOLSDIR%\xuetr\PCHunterCmd%ARCH%.exe

REM ==============================================================
REM
REM Code.

mkdir %LOGDIR%

REM Import SysInternals EULAs acceptance markers
::reg import %TOOLSDIR%\eulas.reg

echo     Light System Examination Toolkit (LISET^) > %LOGDIR%\_INFO.txt
echo     Mariusz B. (mariusz.bit@gmail.com^), 2011-2016 >> %LOGDIR%\_INFO.txt
echo     v%VERSION% >> %LOGDIR%\_INFO.txt
echo. >> %LOGDIR%\_INFO.txt
echo Scanning started at: %DATE%, %TIME% >> %LOGDIR%\_INFO.txt
echo Machine's uptime: >> %LOGDIR%\_INFO.txt
%TOOLSDIR%\uptime.exe >> %LOGDIR%\_INFO.txt
echo. >> %LOGDIR%\_INFO.txt
set >> %LOGDIR%\_INFO.txt

echo Logs are to be stored at: %LOGDIR%

echo.
echo ===============================================
echo WARNING.
echo.
echo    Throughout this script there are couple of steps that may take
echo    considerably much more time than other ones. Due to that, you 
echo    are being asked whether you want to include those steps (choose
echo    'Y' when prompted) or to skip them, heading for fast logs collecting
echo    process (choose 'N' in such case).
echo.
set /P LONG_STEPS=Do you want to proceed with long steps? [Y/n]: 
echo.
echo ===============================================

echo Directory to store log files: %LOGDIR%...
echo.

:PHASE0a
REM **** PHASE 0a - Full memory dump
REM
echo.
echo PHASE 0a: Full memory dump (DumpIt RAW format)
echo   Skipping, perform this step manually by using "%TOOLSDIR%\DumpIt.exe" utility.
:: echo ===================================
:: echo    WARNING: When asked - Press 'y' to dump full memory contents (huge output!), or 'n' otherwise.
:: echo    Afterwards, hit [ENTER]
:: echo ===================================
:: echo.
:: echo.
:: %TOOLSDIR%\DumpIt.exe
:: move *.raw %LOGDIR%\ 2> nul


:PHASE0b
REM **** PHASE 0b - Preliminary system's info gathering
REM
echo.
echo PHASE 0b: Preliminary system info gathering.
%TOOLSDIR%\PsInfo.exe /accepteula -h -s -d > %LOGDIR%\SystemInfo0.txt 2> nul

echo   Completed.

:PHASE1

echo.
echo PHASE 1: Collecting forensic traces...
echo           a) Injected DLLs... 
%TOOLSDIR%\InjectedDLL.exe /stext %LOGDIR%\injected_dlls.txt
echo           b) Last activity view...
%TOOLSDIR%\LastActivityView.exe /stext %LOGDIR%\last_activity_view.txt
echo           c) Executed programs list...
%TOOLSDIR%\ExecutedProgramsList.exe /stext %LOGDIR%\executed_programs_list.txt

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE2

REM **** PHASE 2 - Tree view dump
REM
echo.
echo PHASE 2: Collecting files tree list...
echo          a) %SS_PATH1%...
tree "%SS_PATH1%" /F > %LOGDIR%\TREE_1.txt

echo          b) %SS_PATH2%...
tree "%SS_PATH2%" /F > %LOGDIR%\TREE_2.txt

echo          c) %SS_PATH3%...
tree "%SS_PATH3%" /F > %LOGDIR%\TREE_3.txt

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE3

REM **** PHASE 3 - DIR view of SS_PATHs
REM
echo.
echo PHASE 3: Collecting DIR view of the chosen paths...
echo          a) %SS_PATH1%...
dir "%SS_PATH1%" /S > %LOGDIR%\DIR_1.txt

echo          b) %SS_PATH2%...
dir "%SS_PATH2%" /S > %LOGDIR%\DIR_2.txt

echo          c) %SS_PATH3%...
dir "%SS_PATH3%" /S > %LOGDIR%\DIR_3.txt

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE4

REM **** PHASE 4 - Whole list of Services
REM
echo.
echo PHASE 4: Gathering list of services...
sc queryex type= service > %LOGDIR%\LIST_Services1.txt
%TOOLSDIR%\PsService.exe /accepteula > %LOGDIR%\LIST_Services2.txt 2> nul

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE5
REM **** PHASE 5 - Whole list of Drivers
REM
echo.
echo PHASE 5: Gathering list of drivers...
sc queryex type= driver > %LOGDIR%\LIST_Drivers.txt

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE6
REM **** PHASE 6 - WMI database queries
REM
echo.
echo PHASE 6: WMI database queries...

wmic /OUTPUT:"%LOGDIR%\LIST_Processes_WMI1.csv" process list full /format:CSV
wmic /OUTPUT:"%LOGDIR%\LIST_Processes_WMI2-full.txt" process list full
wmic /OUTPUT:"%LOGDIR%\LIST_Processes_WMI3-paths.txt" process get processid,caption,executablepath,commandline /format:LIST
wmic /OUTPUT:"%LOGDIR%\Services-WMI-full.txt" service list full
wmic /OUTPUT:"%LOGDIR%\LIST_Autoruns-WMI.txt" startup list full

if "%LONG_STEPS%" == "n" goto PHASE6COMPLETED
if "%LONG_STEPS%" == "N" goto PHASE6COMPLETED
wmic /OUTPUT:"%LOGDIR%\LIST_Installed_Software.csv" product list full /FORMAT:CSV


:PHASE6COMPLETED
echo   Completed.
REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE7
REM **** PHASE 7 - List of loaded DLLs
REM
echo.
echo PHASE 7: Enumerating list of loaded DLLs...
%TOOLSDIR%\listdlls.exe /accepteula > %LOGDIR%\LIST_DLLs.txt

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE8
REM **** PHASE 8 - Current process list...
REM
echo.
echo PHASE 8: Enumerating currently running processes list...

echo           a) TASKLIST
tasklist /FO TABLE > %LOGDIR%\LIST_Processes_TaskList1.txt
tasklist /FO TABLE /SVC > %LOGDIR%\LIST_Processes_Tasklist2.txt

echo           b) SysInternals PSLIST
%TOOLSDIR%\pslist.exe /accepteula -x > %LOGDIR%\LIST_Processes_PsList_ComplexDetails.txt 2> nul
%TOOLSDIR%\pslist.exe /accepteula -t > %LOGDIR%\LIST_Processes_PsList_TreeView.txt 2> nul

echo           c) XueTr/PCHunter ps
%xuetr% ps > %LOGDIR%\LIST_Processes_XueTr.txt

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE9
REM **** PHASE 9 - MD5 sums of each file in SS_PATHs
REM
echo.
echo PHASE 9: Collecting MD5 sums of every important file...
echo   Skipping, as this step is not that important.
:: echo            Please wait, this is going to take a moment.
:: 
:: echo           a) %SS_PATH1%
:: %TOOLSDIR%\HashMyFiles%ARCH%.exe /folder "%SS_PATH1%" /scomma %LOGDIR%\hash_sums1.csv
:: 
:: echo           b) %SS_PATH2%
:: %TOOLSDIR%\HashMyFiles%ARCH%.exe /folder "%SS_PATH2%" /scomma %LOGDIR%\hash_sums2.csv
:: 
:: echo           c) %SS_PATH3%
:: %TOOLSDIR%\HashMyFiles%ARCH%.exe /folder "%SS_PATH3%" /scomma %LOGDIR%\hash_sums3.csv
:: 
:: echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU

echo.
echo PHASE 10 and 11 (Memory Manager and kernel memory pool dumping) 
echo         are getting skipped due to different purpose of this script.

goto :PHASE12

:: :PHASE10
:: REM **** PHASE 10 - Dump of Actual machine memory
:: echo.
:: echo PHASE 10: Dump entire Physical Memory pool
:: echo     Note: Press ENTER after about 180 seconds !
:: echo     notice: this step will take a little while
:: 
:: set /P t1=Do you want to perform this step (memory dump)? [y/N]:
:: if "%t1%"=="y" goto YES1
:: if "%t1%"=="Y" goto YES1
:: 
:: goto NO1
:: 
:: :YES1
:: pushd %TOOLSDIR%
:: win32dd.exe /d /a /f memory_dump.dmp > ..\%LOGDIR%\LOG_MemoryDump.txt
:: move memory_dump.dmp ..\%LOGDIR%\memory_dump.dmp
:: popd
:: 
:: echo   Completed.
:: 
:: :NO1
:: 
:: REM if "%PERFORM_ALL%" neq "1" goto MENU
:: 
:: 
:: :PHASE11
:: REM **** PHASE 11 - Kernel (BSOD) Memory Dump
:: REM
:: echo.
:: echo PHASE 11: Dump of actual Kernel Memory (BSOD)
:: echo     Note: Press ENTER after about 180 seconds !
:: echo     notice: this step will take a little while
:: 
:: set /P t1=Do you want to perform this step (kernel dump)? [y/N]:
:: if "%t1%"=="y" goto YES2
:: if "%t1%"=="Y" goto YES2
:: 
:: goto NO2
:: 
:: :YES2
:: pushd %TOOLSDIR%
:: win32dd.exe /k /a /f kernel_memory_dump.dmp > ..\%LOGDIR%\LOG_KernelMemDump.txt
:: move kernel_memory_dump.dmp ..\%LOGDIR%\kernel_memory_dump.dmp
:: popd
:: 
:: echo   Completed.
:: 
:: :NO2
:: 
:: REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE12
REM **** PHASE 12 - Complete log from netstat
echo.
echo PHASE 12: Gathering complete list of open connections from netstat
netstat -e > %LOGDIR%\LOG_NETSTAT.txt
echo ------------------------ >> %LOGDIR%\LOG_NETSTAT.txt
netstat -r >> %LOGDIR%\LOG_NETSTAT.txt
echo ------------------------ >> %LOGDIR%\LOG_NETSTAT.txt
netstat -abfo >> %LOGDIR%\LOG_NETSTAT.txt

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE13
REM **** PHASE 13 - DNS Cache list
REM
echo.
echo PHASE 13: DNS Cache list dump
ipconfig /displaydns > %LOGDIR%\LIST_DNSCache.txt

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE14
REM **** PHASE 14 - ARP Routing table
REM
echo.
echo PHASE 14: ARP Routing table dump
arp -a > %LOGDIR%\LIST_ARP_RoutingTable.txt

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE15

echo.

%xuetr% | findstr /B /C:"Load Driver Error" > nul
IF %errorlevel% NEQ 0 (
    echo PHASE 15 is being skipped due to XueTr driver's loading failure.
) ELSE (
    echo PHASE 15: XueTr/PCHunter logs gathering
    %xuetr% lkm > %LOGDIR%\xuetr_lkm.txt
    %xuetr% ssdt > %LOGDIR%\xuetr_ssdt.txt
    %xuetr% shadowssdt > %LOGDIR%\xuetr_shadowssdt.txt
    %xuetr% fsd > %LOGDIR%\xuetr_fsd.txt
    %xuetr% tcpip > %LOGDIR%\xuetr_tcpip.txt
    %xuetr% kbd > %LOGDIR%\xuetr_kbd.txt
    %xuetr% idt > %LOGDIR%\xuetr_idt.txt
    %xuetr% objecttype > %LOGDIR%\xuetr_objecttype.txt
    %xuetr% objecttype_callback > %LOGDIR%\xuetr_objecttype_callback.txt
    %xuetr% hhive > %LOGDIR%\xuetr_hhive.txt
    %xuetr% callback > %LOGDIR%\xuetr_callback.txt
    %xuetr% nr > %LOGDIR%\xuetr_nr.txt
    %xuetr% port > %LOGDIR%\xuetr_port.txt
    %xuetr% mbr > %LOGDIR%\xuetr_mbr.txt
    %xuetr% classpnp > %LOGDIR%\xuetr_classpnp.txt
    %xuetr% atapi > %LOGDIR%\xuetr_atapi.txt
    %xuetr% acpi > %LOGDIR%\xuetr_acpi.txt
    %xuetr% dpctimer > %LOGDIR%\xuetr_dpctimer.txt
    %xuetr% filter > %LOGDIR%\xuetr_filter.txt
    %xuetr% kernelhook > %LOGDIR%\xuetr_kernelhook.txt
    %xuetr% scsi > %LOGDIR%\xuetr_scsi.txt
    %xuetr% mouse > %LOGDIR%\xuetr_mouse.txt
    %xuetr% npfs > %LOGDIR%\xuetr_npfs.txt
    %xuetr% msfs > %LOGDIR%\xuetr_msfs.txt
    %xuetr% usbport > %LOGDIR%\xuetr_usbport.txt
    %xuetr% i8042prt > %LOGDIR%\xuetr_i8042prt.txt
    %xuetr% hdt > %LOGDIR%\xuetr_hdt.txt
    %xuetr% hpdt > %LOGDIR%\xuetr_hpdt.txt
    %xuetr% hadt > %LOGDIR%\xuetr_hadt.txt
    %xuetr% wdf01000 > %LOGDIR%\xuetr_wdf01000.txt
    %xuetr% wdff > %LOGDIR%\xuetr_wdff.txt
    %xuetr% fmf > %LOGDIR%\xuetr_fmf.txt
    %xuetr% fs > %LOGDIR%\xuetr_fs.txt
    %xuetr% fst > %LOGDIR%\xuetr_fst.txt
    %xuetr% cid > %LOGDIR%\xuetr_cid.txt
    %xuetr% ckdr > %LOGDIR%\xuetr_ckdr.txt
    %xuetr% cdrx > %LOGDIR%\xuetr_cdrx.txt
    %xuetr% objhij > %LOGDIR%\xuetr_objhij.txt
    %xuetr% nsiproxy > %LOGDIR%\xuetr_nsiproxy.txt
    %xuetr% tdx > %LOGDIR%\xuetr_tdx.txt
    %xuetr% ndis > %LOGDIR%\xuetr_ndis.txt
)

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE16
REM **** PHASE 16 - Autoruns
REM

echo.
echo PHASE 16: Collecting and briefly analysing AUTORUN values...
echo           notice: This step may take a while, please be patient.

if "%LONG_STEPS%" == "n" goto PHASE16B
if "%LONG_STEPS%" == "N" goto PHASE16B

%TOOLSDIR%\autorunsc.exe /accepteula -a dehiklst -h -m -s -u > %LOGDIR%\LIST_Autoruns0.txt 2> nul
%TOOLSDIR%\autorunsc.exe /accepteula -a * -h -m -s -u > %LOGDIR%\LIST_Autoruns1.txt 2> nul

goto PHASE16COMPLETED

:PHASE16B
echo   (Warning: Collecting autorun entries without signature validation due to
echo   user choice to omit long steps)
%TOOLSDIR%\autorunsc.exe /accepteula -a dehiklst -h -m > %LOGDIR%\LIST_Autoruns0b.txt 2> nul

:PHASE16COMPLETED
echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE17
REM **** PHASE 17 - Copy of MBR
REM
echo.
echo PHASE 17: Copying Master+Volume Boot Record (MBR/VBR) binary...
echo   Skipping due to problems with cross-platform TSK FLS/icat workings.
:: echo           Examining file's system meta-structure...
:: %TOOLSDIR%\fls.exe \\.\%SYSTEMDRIVE% > %LOGDIR%\fls_SystemDrive.txt
:: 
:: set bootnum=0
:: for /f "tokens=2,3* delims= " %%i in ('more %LOGDIR%\fls_SystemDrive.txt') do (
::     if "%%j" == "$Boot" for /f "tokens=1 delims=:" %%n in ('echo %%i') do (
::         set bootnum=%%n
::     )
:: )
:: 
:: echo           Dumping NTFS $Boot file (\\.\%SYSTEMDRIVE% inode:%bootnum%)...
:: %TOOLSDIR%\icat.exe \\.\%SYSTEMDRIVE% %bootnum% > %LOGDIR%\boot_file.bin
:: 
:: echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE18
REM **** PHASE 18 - Whole system registered handles list
REM
echo.
echo PHASE 18: Whole system registered handles list dumping...
%TOOLSDIR%\handle /accepteula -s > %LOGDIR%\LIST_Handles.txt
echo . >> %LOGDIR%\LIST_Handles.txt
%TOOLSDIR%\handle /accepteula -a >> %LOGDIR%\LIST_Handles.txt

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE19
REM **** PHASE 19 - Every drive NTFS info
REM
echo.
echo PHASE 19: Every drive's NTFS info
echo    [-] Currently Not Available.

REM echo PHASE 19: Collecting every drive NTFS info

:PHASE20

REM **** PHASE 20: Open ports list
REM
echo.
echo PHASE 20: Open ports list

REM %TOOLSDIR%\cports%ARCH%.exe /stext %LOGDIR%\PORTS_List.txt
%TOOLSDIR%\cports.exe /stext %LOGDIR%\PORTS_List.txt

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU

:PHASE21

REM **** PHASE 21: Current logged on users list
REM
echo.
echo PHASE 21: Currently Logged on users list
%TOOLSDIR%\PsLoggedon.exe /accepteula > %LOGDIR%\LoggedOn_List.txt 2> nul

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE22

REM **** PHASE 22: Simple copy of hosts file
REM
echo.
echo PHASE 22: HOSTS file.
copy %SYSTEMROOT%\System32\drivers\etc\hosts %LOGDIR%\hosts.txt > nul

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE23

REM **** PHASE 23: Possible FIREWALL filters (netsh)
REM 
echo.
echo PHASE 23: Possible FIREWALL filters (netsh^)

netsh firewall show config > %LOGDIR%\netsh_firewall0.txt
netsh advfirewall firewall show rule name=all > %LOGDIR%\netsh_firewall_all.txt

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE24

REM **** PHASE 24: Complete SYSTEMINFO log
REM
echo.
echo PHASE 24: Complete SYSTEMINFO log
systeminfo /FO list > %LOGDIR%\SystemInfo.txt

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU

:PHASE25

if "%LONG_STEPS%" == "n" goto PHASE26
if "%LONG_STEPS%" == "N" goto PHASE26

echo.
echo PHASE 25: Alternate Data Streams scan...
echo     notice: this step will take a while. Please, be patient.
echo.
echo           a) %SS_PATH1%...
%TOOLSDIR%\streams.exe /accepteula -s "%SS_PATH1%" > %LOGDIR%\LIST_ADS_1.txt

echo           b) %SS_PATH2%...
%TOOLSDIR%\streams.exe /accepteula -s "%SS_PATH2%" > %LOGDIR%\LIST_ADS_2.txt

echo           c) %SS_PATH3%...
%TOOLSDIR%\streams.exe /accepteula -s "%SS_PATH3%" > %LOGDIR%\LIST_ADS_3.txt

echo   Completed.
echo.

REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE26

if "%LONG_STEPS%" == "n" goto PHASE27
if "%LONG_STEPS%" == "N" goto PHASE27

REM **** PHASE 26 - Registry dump
echo.
echo PHASE 26: Dumping registry Hives...
echo          a) HKCU export...
reg export HKCU %LOGDIR%\HKCU_export.reg > nul 2> nul

echo          b) HKCR export...
reg export HKCR %LOGDIR%\HKCR_export.reg > nul 2> nul

echo          c) HKCC export
reg export HKCC %LOGDIR%\HKCC_export.reg > nul 2> nul

echo          d) HKU export
reg export HKU %LOGDIR%\HKU_export.reg > nul 2> nul

echo          e) HKLM export (this one takes a longer while)...
reg export HKLM %LOGDIR%\HKLM_export.reg > nul 2> nul

echo   Completed.


REM if "%PERFORM_ALL%" neq "1" goto MENU


:PHASE27

if "%LONG_STEPS%" == "n" goto PHASE28
if "%LONG_STEPS%" == "N" goto PHASE28

echo.
echo PHASE 27: Signature recursive files scanning and verifying...
echo     notice: this step will take a much LONGER while. Please, be patient!
echo.
echo           a) %SS_PATH1%...
%TOOLSDIR%\sigcheck.exe /accepteula -a -e -h -q -u -vt -v "%SS_PATH1%" > %LOGDIR%\sigcheck_1.txt
%TOOLSDIR%\sigcheck.exe /accepteula -a -e -h -q -u -vt -v "%SS_PATH1%\System32" > %LOGDIR%\sigcheck_1.txt
echo           b) %SS_PATH2%...
%TOOLSDIR%\sigcheck.exe /accepteula -h -q -r -s -u "%SS_PATH2%" > %LOGDIR%\sigcheck_2.txt
echo           c) %SS_PATH3%...
%TOOLSDIR%\sigcheck.exe /accepteula -e -h -q -r -s -u "%SS_PATH3%" > %LOGDIR%\sigcheck_3.txt

echo   Completed.

REM if "%PERFORM_ALL%" neq "1" goto MENU

:PHASE28

:FINISH

REM *** LAST PHASE - 7z compressing

echo.
echo.
echo LAST PHASE: Compressing the logs directory
echo     notice: this step may take a little while
%TOOLSDIR%\7z.exe a %LOGDIR% %LOGDIR% 2> nul > nul
move %LOGDIR%.7z %cd%\LISET_LOGS.7z > nul
del /S /F /Q %LOGDIR% 2> nul > nul
rmdir %LOGDIR% 2> nul > nul

echo.
echo   Script has finished it's execution.
echo   Logs stored at: %cd%\LISET_LOGS.7z 
echo.

:END
