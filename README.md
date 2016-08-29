# LISET
Light System Examination Toolkit (LISET) - logs &amp; activity &amp; configuration gathering utility that comes handy in fast Windows incident response (either forensic or malware oriented).

### What the heck is it?

This is a script intended to be run during incident analysis or after malware infection. It gathers logs from several commands and tools, that will be used to produce a package with most valuable informations about system's enviroment after an incident. Such package containing logs could be later on send to computer forensics or malware analysis expert for examination.

This script uses several utilies from SysInternalsSuite, Matthieu Suiche DumpIt, XueTr/PCHunter command line version and 7zip command line packer.


### List of phases

```
This script collects information about system from different
locations. It gathers:
 x - not implemented yet
 s - skipped
 c - conditional (long steps)
 d - disabled code

d 0a. Full memory dump
0b. Preliminary system informations gathering
1. Collecting some forensics traces
2. Tree view of SS_PATHs
3. DIR view of SS_PATHs
4. Whole list of running (and not) services
5. Whole list of running (and not) drivers
6. WMI database queries.
7. List of running/loaded/unloaded DLLs
8. Current PROCESS List (from 3 different collectors):
	 * system tasklist
	 * WMI database
	 * Sysinternals PSLIST
 	 * and any extra source
s 9. MD5 sums of each file in SS_PATHs
s 10. Dump of actual machine memory (win32dd)
s 11. Dump of actual kernel memory (Crash Dump)
12. Complete log from netstat
13. DNS Cache list (ipconfig /flushdns )
14. ARP Routing Table
15. XueTr/PCHunter logs gathering
16. Simple autorun values list (simple view format)
s 17. Copy of Master Boot Record
18. Whole system registered Handles list
x 19. Every drive NTFS info
20. Open ports list (through TCPVcon.exe)
21. Current logged in users list
22. Simple copy of hosts file
23. Possible FIREWALL filters (netsh)
24. Complete SYSTEMINFO log
c 25. List of every spotted Alternate Data Stream in SS_PATHs
c 26.  Dump of registry Keys (Exports)
c 27. Sigcheck recursive files scanning

Then script will move all gathered log files into one folder
and pack this folder (zip or something) and compare MD5 checksums
```


PS: Some day it is going to be written from a scratch in PowerShell. For now, in order to be backwards-compatible with WinXP - batch will remain.
