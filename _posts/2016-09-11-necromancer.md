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
