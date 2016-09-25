---
layout: post
title: "Platypuscon CTF write up"
description: "Platypuscon CTF write up"
category: writeups, ctfs
tags: [platypuscon, ctf, writeups, syn-wave]
---
So this weekend the Playpus Initiative had their first conference and for their first managed to pull off quite a conference. They had 4 streams of talks and all of them were interactive. I spent an hour playing the CTF where I was able to complete a few challenges. This blog post will detail my working notes as I solve the challenges.

# syn-wave
The first challenge was in the form of a packet capture.

```
root@kali:~/192.168.5.206/syn-wave# ls -ltr
total 412
-rw-r--r-- 1 root root 184984 Sep 22 07:25 syn-wave.pcapng
-rw-r--r-- 1 root root     51 Sep 22 07:44 syn-wave.pcapng.md5
-rw-r--r-- 1 root root    413 Sep 24 01:11 index.html
```

Reading the packet capture using tshark shows that the capture is mostly TCP Retransmissions

```
root@kali:~/192.168.5.206/syn-wave# tshark -r syn-wave.pcapng
Running as user "root" and group "root". This could be dangerous.
  1 0.000000000 192.168.67.128 -> 192.168.67.129 TCP 62 40508 > 40508 [SYN] Seq=0 Win=8192 Len=0
  2 0.056665000 192.168.67.128 -> 192.168.67.129 TCP 58 [TCP Retransmission] 40508 > 40508 [SYN] Seq=0 Win=8192 Len=0
  3 0.140858000 192.168.67.128 -> 192.168.67.129 TCP 62 [TCP Retransmission] 40508 > 40508 [SYN] Seq=0 Win=8192 Len=0
---8<---
1964 644.315502000 192.168.67.128 -> 192.168.67.129 TCP 58 [TCP Retransmission] 40508 > 40508 [SYN] Seq=0 Win=8192 Len=0
1965 646.481268000 192.168.67.128 -> 192.168.67.129 TCP 62 [TCP Retransmission] 40508 > 40508 [SYN] Seq=0 Win=8192 Len=0
1966 648.624433000 192.168.67.128 -> 192.168.67.129 TCP 58 [TCP Retransmission] 40508 > 40508 [SYN] Seq=0 Win=8192 Len=0
```

Loading the file into wireshark we see something interesting in the first frame. It looks like a PNG header encoded into the tcp options section of the header.

<img src="{{site.url}}/assets/platypuscon-1-syn-wave-1.png">

Looking through the other frames we see other parts of the PNG header like the IHDR headers.

<img src="{{site.url}}/assets/platypuscon-1-syn-wave-2.png">

Switching back to a terminal I used tshark to extract all of the values from the TCP options header. It appears that a png image is being encoded into the last 4 bytes of the tcp options headers of every other frame.

```
root@kali:~/192.168.5.206/syn-wave# tshark -r syn-wave.pcapng -T fields -e tcp.options
Running as user "root" and group "root". This could be dangerous.
19:08:34:3a:89:50:4e:47
19:03:54:00
19:08:34:3a:0d:0a:1a:0a
19:03:77:00
19:08:34:3a:00:00:00:0d
19:03:6f:00
19:08:34:3a:49:48:44:52
19:03:20:00
19:08:34:3a:00:00:02:94
---8<---
root@kali:~/192.168.5.206/syn-wave# tshark -r syn-wave.pcapng -T fields -e tcp.options | tr -d ':' | head -n 9 | xxd -r -p | hexdump -C
Running as user "root" and group "root". This could be dangerous.
00000000  19 08 34 3a 89 50 4e 47  19 03 54 00 19 08 34 3a  |..4:.PNG..T...4:|
00000010  0d 0a 1a 0a 19 03 77 00  19 08 34 3a 00 00 00 0d  |......w...4:....|
00000020  19 03 6f 00 19 08 34 3a  49 48 44 52 19 03 20 00  |..o...4:IHDR.. .|
00000030  19 08 34 3a 00 00 02 94                           |..4:....|
00000038
```

With the encoding and pattern figured out, I was able to extract the image by using the following command.

```
root@kali:~/192.168.5.206/syn-wave# tshark -r syn-wave.pcapng -T fields -e tcp.options | cut -d: -f5- | tr -d '\n' | tr -d ':' | xxd -r -p > image.png
Running as user "root" and group "root". This could be dangerous.
```

Opening the image reveals the flag.

<img src="{{site.url}}/assets/platypuscon-1-syn-wave-3.png">

# cinderblock

The file that provided to us was named cinderblock.png.

```
root@kali:~/192.168.5.206/rorikstead# ls -l
total 496
-rw-r--r-- 1 root root 468534 Sep 17 07:52 cinderblock.png
-rw-r--r-- 1 root root     51 Sep 22 07:49 cinderblock.png.md5
-rw-r--r-- 1 root root    417 Sep 24 01:11 index.html
```

Viewing the image didn't reveal anything besides the alphet cubes and the word chaos.

<img src="{{site.url}}/assets/platypuscon-1-cinderblock-1.png">

Checking the file metadata using exiftool didn't reveal anything.

```
root@kali:~/192.168.5.206/rorikstead# file cinderblock.png
cinderblock.png: PNG image data, 620 x 421, 8-bit/color RGB, non-interlaced
root@kali:~/192.168.5.206/rorikstead# exiftool cinderblock.png
ExifTool Version Number         : 8.60
File Name                       : cinderblock.png
Directory                       : .
File Size                       : 458 kB
File Modification Date/Time     : 2016:09:17 07:52:56-04:00
File Permissions                : rw-r--r--
File Type                       : PNG
MIME Type                       : image/png
Image Width                     : 620
Image Height                    : 421
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Profile CMM Type                : appl
Profile Version                 : 2.1.0
Profile Class                   : Display Device Profile
Color Space Data                : RGB
Profile Connection Space        : XYZ
Profile Date Time               : 2012:01:02 17:01:03
Profile File Signature          : acsp
Primary Platform                : Apple Computer Inc.
CMM Flags                       : Not Embedded, Independent
Device Manufacturer             : 
Device Model                    : 
Device Attributes               : Reflective, Glossy, Positive, Color
Rendering Intent                : Perceptual
Connection Space Illuminant     : 0.9642 1 0.82491
Profile Creator                 : appl
Profile ID                      : 0
Profile Description             : Display
Profile Description ML          : Color LCD
Profile Copyright               : Copyright Apple, Inc., 2012
Media White Point               : 0.95047 1 1.0891
Red Matrix Column               : 0.43434 0.22417 0.00591
Green Matrix Column             : 0.37863 0.71646 0.03152
Blue Matrix Column              : 0.15123 0.05936 0.78746
Red Tone Reproduction Curve     : (Binary data 2060 bytes, use -b option to extract)
Video Card Gamma                : (Binary data 1554 bytes, use -b option to extract)
Native Display Info             : (Binary data 1598 bytes, use -b option to extract)
Chromatic Adaptation            : 1.04788 0.02292 -0.0502 0.02957 0.99049 -0.01706 -0.00923 0.01508 0.75165
Make And Model                  : (Binary data 40 bytes, use -b option to extract)
Blue Tone Reproduction Curve    : (Binary data 2060 bytes, use -b option to extract)
Green Tone Reproduction Curve   : (Binary data 2060 bytes, use -b option to extract)
Pixels Per Unit X               : 2835
Pixels Per Unit Y               : 2835
Pixel Units                     : Meters
Image Size                      : 620x421
```

However binwalk did turn up an embedded elf file.

```
root@kali:~/192.168.5.206/rorikstead# binwalk cinderblock.png
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 620 x 421, 8-bit/color RGB, non-interlaced
251829        0x3D7B5         LZMA compressed data, properties: 0x5D, dictionary size: 2097152 bytes, missing uncompressed size
459542        0x70316         ELF 64-bit LSB executable, AMD x86-64, version 1 (SYSV)
467382        0x721B6         LZMA compressed data, properties: 0x89, dictionary size: 16777216 bytes, uncompressed size: 100663296 bytes
467510        0x72236         LZMA compressed data, properties: 0x9A, dictionary size: 16777216 bytes, uncompressed size: 100663296 bytes
467702        0x722F6         LZMA compressed data, properties: 0xB6, dictionary size: 16777216 bytes, uncompressed size: 33554432 bytes
467894        0x723B6         LZMA compressed data, properties: 0xD8, dictionary size: 16777216 bytes, uncompressed size: 50331648 bytes
```

I proceed to carve the file out by hand using dd.

```
root@kali:~/192.168.5.206/rorikstead# dd if=cinderblock.png of=459542.elf skip=459542 bs=1
8992+0 records in
8992+0 records out
8992 bytes (9.0 kB) copied, 0.0356289 s, 252 kB/s
```

Running file against the file confirms that it's a 64bit binary.

```
root@kali:~/192.168.5.206/rorikstead# file 459542.elf
459542.elf: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=0x43ad3950928346a88e4e302428ec47f79ec6d371, not stripped
```

Running strings against the binary reveals that it's likely going to ask for four inputs and decrypt something.

```
root@kali:~/192.168.5.206/rorikstead# strings a.elf 
/lib64/ld-linux-x86-64.so.2
libc.so.6
__isoc99_scanf
printf
mprotect
malloc
__libc_start_main
__gmon_start__
---8<---
 enter the four keys > 
%x %x %x %x
 decrypting with keys %02x %02x %02x %02x...
;*3$"
```

# jackbenimble

The file provided is an exe named jackbenimble.exe.

```
root@kali:~/192.168.5.206/soenterprise# ls -lh
total 40K
-rw-r--r-- 1 root root 423 Sep 24 01:11 index.html
-rw-r--r-- 1 root root 32K Sep 17 07:52 jackbenimble.exe
-rw-r--r-- 1 root root  67 Sep 22 07:47 jackbenimble.exe.md5
```

Running file against the binary shows that it's a 32 bit windows executable.

```
root@kali:~/192.168.5.206/soenterprise# file jackbenimble.exe
jackbenimble.exe: PE32 executable (GUI) Intel 80386, for MS Windows
```

Running string against the binary reveals a couple of interesting things.

* The binary was written in Visual C++
* There is a win condition(password)
* The flag is the md5sum of the password
* There appears to be antidebugging(IsDebuggerPresent)

```
root@kali:~/192.168.5.206/soenterprise# strings jackbenimble.exe
---8<---
Microsoft Visual C++ Runtime Library
This application has requested the Runtime to terminate it in an unusual way.
Please contact the application's support team for more information.
Winner!
$LJHS${md5sum_of_the_password}$
---8<---
GetAsyncKeyState
MessageBoxA
USER32.dll
IsDebuggerPresent
GetProcAddress
GetModuleHandleW
ExitProcess
DecodePointer
GetCommandLineA
HeapSetInformation
GetStartupInfoW
InitializeCriticalSectionAndSpinCount
DeleteCriticalSection
LeaveCriticalSection
EnterCriticalSection
EncodePointer
GetLastError
LoadLibraryW
UnhandledExceptionFilter
SetUnhandledExceptionFilter
TerminateProcess
GetCurrentProcess
TlsAlloc
TlsGetValue
TlsSetValue
TlsFree
InterlockedIncrement
SetLastError
GetCurrentThreadId
InterlockedDecrement
WriteFile
GetStdHandle
GetModuleFileNameW
GetModuleFileNameA
FreeEnvironmentStringsW
WideCharToMultiByte
GetEnvironmentStringsW
SetHandleCount
GetFileType
HeapCreate
QueryPerformanceCounter
GetTickCount
GetCurrentProcessId
GetSystemTimeAsFileTime
HeapFree
Sleep
GetCPInfo
GetACP
GetOEMCP
IsValidCodePage
HeapSize
RtlUnwind
HeapAlloc
HeapReAlloc
IsProcessorFeaturePresent
LCMapStringW
MultiByteToWideChar
GetStringTypeW
KERNEL32.dll
---8<---
```

I then threw the binary in radare2 to analyse further.

```
root@kali:~/192.168.5.206/soenterprise# radare2 jackbenimble.exe
[0x00401509]> aaaa
[0x00401509]> ii
[Imports]
addr=0x004060e0 off=0x00004ae0 ordinal=000 hint=526 bind=NONE type=FUNC name=USER32.dll_MessageBoxA
addr=0x004060e4 off=0x00004ae4 ordinal=000 hint=263 bind=NONE type=FUNC name=USER32.dll_GetAsyncKeyState
addr=0x00406000 off=0x00004a00 ordinal=000 hint=453 bind=NONE type=FUNC name=KERNEL32.dll_GetCurrentThreadId
addr=0x00406004 off=0x00004a04 ordinal=000 hint=617 bind=NONE type=FUNC name=KERNEL32.dll_GetStringTypeW
addr=0x00406008 off=0x00004a08 ordinal=000 hint=871 bind=NONE type=FUNC name=KERNEL32.dll_MultiByteToWideChar
addr=0x0040600c off=0x00004a0c ordinal=000 hint=768 bind=NONE type=FUNC name=KERNEL32.dll_IsDebuggerPresent
addr=0x00406010 off=0x00004a10 ordinal=000 hint=581 bind=NONE type=FUNC name=KERNEL32.dll_GetProcAddress
addr=0x00406014 off=0x00004a14 ordinal=000 hint=536 bind=NONE type=FUNC name=KERNEL32.dll_GetModuleHandleW
addr=0x00406018 off=0x00004a18 ordinal=000 hint=281 bind=NONE type=FUNC name=KERNEL32.dll_ExitProcess
addr=0x0040601c off=0x00004a1c ordinal=000 hint=202 bind=NONE type=FUNC name=KERNEL32.dll_DecodePointer
addr=0x00406020 off=0x00004a20 ordinal=000 hint=390 bind=NONE type=FUNC name=KERNEL32.dll_GetCommandLineA
addr=0x00406024 off=0x00004a24 ordinal=000 hint=723 bind=NONE type=FUNC name=KERNEL32.dll_HeapSetInformation
addr=0x00406028 off=0x00004a28 ordinal=000 hint=611 bind=NONE type=FUNC name=KERNEL32.dll_GetStartupInfoW
addr=0x0040602c off=0x00004a2c ordinal=000 hint=739 bind=NONE type=FUNC name=KERNEL32.dll_InitializeCriticalSectionAndSpinCount
addr=0x00406030 off=0x00004a30 ordinal=000 hint=209 bind=NONE type=FUNC name=KERNEL32.dll_DeleteCriticalSection
addr=0x00406034 off=0x00004a34 ordinal=000 hint=825 bind=NONE type=FUNC name=KERNEL32.dll_LeaveCriticalSection
addr=0x00406038 off=0x00004a38 ordinal=000 hint=238 bind=NONE type=FUNC name=KERNEL32.dll_EnterCriticalSection
addr=0x0040603c off=0x00004a3c ordinal=000 hint=234 bind=NONE type=FUNC name=KERNEL32.dll_EncodePointer
addr=0x00406040 off=0x00004a40 ordinal=000 hint=514 bind=NONE type=FUNC name=KERNEL32.dll_GetLastError
addr=0x00406044 off=0x00004a44 ordinal=000 hint=831 bind=NONE type=FUNC name=KERNEL32.dll_LoadLibraryW
addr=0x00406048 off=0x00004a48 ordinal=000 hint=1235 bind=NONE type=FUNC name=KERNEL32.dll_UnhandledExceptionFilter
addr=0x0040604c off=0x00004a4c ordinal=000 hint=1189 bind=NONE type=FUNC name=KERNEL32.dll_SetUnhandledExceptionFilter
addr=0x00406050 off=0x00004a50 ordinal=000 hint=1216 bind=NONE type=FUNC name=KERNEL32.dll_TerminateProcess
addr=0x00406054 off=0x00004a54 ordinal=000 hint=448 bind=NONE type=FUNC name=KERNEL32.dll_GetCurrentProcess
addr=0x00406058 off=0x00004a58 ordinal=000 hint=1221 bind=NONE type=FUNC name=KERNEL32.dll_TlsAlloc
addr=0x0040605c off=0x00004a5c ordinal=000 hint=1223 bind=NONE type=FUNC name=KERNEL32.dll_TlsGetValue
addr=0x00406060 off=0x00004a60 ordinal=000 hint=1224 bind=NONE type=FUNC name=KERNEL32.dll_TlsSetValue
addr=0x00406064 off=0x00004a64 ordinal=000 hint=1222 bind=NONE type=FUNC name=KERNEL32.dll_TlsFree
addr=0x00406068 off=0x00004a68 ordinal=000 hint=751 bind=NONE type=FUNC name=KERNEL32.dll_InterlockedIncrement
addr=0x0040606c off=0x00004a6c ordinal=000 hint=1139 bind=NONE type=FUNC name=KERNEL32.dll_SetLastError
addr=0x00406070 off=0x00004a70 ordinal=000 hint=747 bind=NONE type=FUNC name=KERNEL32.dll_InterlockedDecrement
addr=0x00406074 off=0x00004a74 ordinal=000 hint=1317 bind=NONE type=FUNC name=KERNEL32.dll_WriteFile
addr=0x00406078 off=0x00004a78 ordinal=000 hint=612 bind=NONE type=FUNC name=KERNEL32.dll_GetStdHandle
addr=0x0040607c off=0x00004a7c ordinal=000 hint=532 bind=NONE type=FUNC name=KERNEL32.dll_GetModuleFileNameW
addr=0x00406080 off=0x00004a80 ordinal=000 hint=531 bind=NONE type=FUNC name=KERNEL32.dll_GetModuleFileNameA
addr=0x00406084 off=0x00004a84 ordinal=000 hint=353 bind=NONE type=FUNC name=KERNEL32.dll_FreeEnvironmentStringsW
addr=0x00406088 off=0x00004a88 ordinal=000 hint=1297 bind=NONE type=FUNC name=KERNEL32.dll_WideCharToMultiByte
addr=0x0040608c off=0x00004a8c ordinal=000 hint=474 bind=NONE type=FUNC name=KERNEL32.dll_GetEnvironmentStringsW
addr=0x00406090 off=0x00004a90 ordinal=000 hint=1135 bind=NONE type=FUNC name=KERNEL32.dll_SetHandleCount
addr=0x00406094 off=0x00004a94 ordinal=000 hint=499 bind=NONE type=FUNC name=KERNEL32.dll_GetFileType
addr=0x00406098 off=0x00004a98 ordinal=000 hint=717 bind=NONE type=FUNC name=KERNEL32.dll_HeapCreate
addr=0x0040609c off=0x00004a9c ordinal=000 hint=935 bind=NONE type=FUNC name=KERNEL32.dll_QueryPerformanceCounter
addr=0x004060a0 off=0x00004aa0 ordinal=000 hint=659 bind=NONE type=FUNC name=KERNEL32.dll_GetTickCount
addr=0x004060a4 off=0x00004aa4 ordinal=000 hint=449 bind=NONE type=FUNC name=KERNEL32.dll_GetCurrentProcessId
addr=0x004060a8 off=0x00004aa8 ordinal=000 hint=633 bind=NONE type=FUNC name=KERNEL32.dll_GetSystemTimeAsFileTime
addr=0x004060ac off=0x00004aac ordinal=000 hint=719 bind=NONE type=FUNC name=KERNEL32.dll_HeapFree
addr=0x004060b0 off=0x00004ab0 ordinal=000 hint=1202 bind=NONE type=FUNC name=KERNEL32.dll_Sleep
addr=0x004060b4 off=0x00004ab4 ordinal=000 hint=370 bind=NONE type=FUNC name=KERNEL32.dll_GetCPInfo
addr=0x004060b8 off=0x00004ab8 ordinal=000 hint=360 bind=NONE type=FUNC name=KERNEL32.dll_GetACP
addr=0x004060bc off=0x00004abc ordinal=000 hint=567 bind=NONE type=FUNC name=KERNEL32.dll_GetOEMCP
addr=0x004060c0 off=0x00004ac0 ordinal=000 hint=778 bind=NONE type=FUNC name=KERNEL32.dll_IsValidCodePage
addr=0x004060c4 off=0x00004ac4 ordinal=000 hint=724 bind=NONE type=FUNC name=KERNEL32.dll_HeapSize
addr=0x004060c8 off=0x00004ac8 ordinal=000 hint=1048 bind=NONE type=FUNC name=KERNEL32.dll_RtlUnwind
addr=0x004060cc off=0x00004acc ordinal=000 hint=715 bind=NONE type=FUNC name=KERNEL32.dll_HeapAlloc
addr=0x004060d0 off=0x00004ad0 ordinal=000 hint=722 bind=NONE type=FUNC name=KERNEL32.dll_HeapReAlloc
addr=0x004060d4 off=0x00004ad4 ordinal=000 hint=772 bind=NONE type=FUNC name=KERNEL32.dll_IsProcessorFeaturePresent
addr=0x004060d8 off=0x00004ad8 ordinal=000 hint=813 bind=NONE type=FUNC name=KERNEL32.dll_LCMapStringW

57 imports
vv
```
