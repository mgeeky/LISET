# LISET
Light System Examination Toolkit (LISET) - logs &amp; activity &amp; configuration gathering utility that comes handy in fast Windows incident response (either forensic or malware oriented).

### What the heck is it?

This is a script intended to be run during incident analysis or after malware infection. It gathers logs from several commands and tools, that will be used to produce a package with most valuable informations about system's enviroment after an incident. Such package containing logs could be later on send to computer forensics or malware analysis expert for examination.

This script uses several utilies from SysInternalsSuite, Matthieu Suiche DumpIt, XueTr/PCHunter command line version and 7zip command line packer.


### List of phases

```
0a. Full memory dump
0b. Preliminary system informations gathering
1.  Dump of registry Keys (Exports)
2.  Tree view of SS_PATHs
3.  DIR view of SS_PATHs
4.  Whole list of running (and not) services
5.  Whole list of running (and not) drivers
6.  List of running/loaded/unloaded DLLs
7.  Current PROCESS List (from 3 different collectors):
	 * system tasklist
	 * Sysinternals PSLIST
 	 * and any extra source
8.  MD5 sums of each file in SS_PATHs
9.  Dump of actual machine memory (win32dd)
10. Dump of actual kernel memory (Crash Dump)
11. Complete log from netstat
12. DNS Cache list (ipconfig /flushdns )
13. ARP Routing Table
14. List of every spotted Alternate Data Stream in SS_PATHs
15. Simple autorun values list (simple view format)
16. Copy of Master Boot Record
17. Whole system registered Handles list
x 18. Every drive NTFS info
19. Open ports list (through TCPVcon.exe)
20. Current logged in users list
21. Simple copy of hosts file
22. Possible FIREWALL filters (netsh)
23. Complete SYSTEMINFO log
24. XueTr/PCHunter logs gathering
25. Sigcheck recursive files scanning
```
