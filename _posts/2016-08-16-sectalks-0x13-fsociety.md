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

* The binary start spawn a shell
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

# TODO: Complete second challenge
