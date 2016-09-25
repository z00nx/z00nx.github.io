---
layout: post
title: "Platypuscon CTF write up"
description: "Platypuscon CTF write up"
category: writeups, ctfs
tags: [platypuscon, ctf, writeups, syn-wave]
---
So this weekend the Playpus Initiative had their first conference and for their first managed to pull off quite a conference. They had 4 streams of talks and all of them were interactive. I spent an hour playing the CTF where I was able to complete a few challenges.

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
