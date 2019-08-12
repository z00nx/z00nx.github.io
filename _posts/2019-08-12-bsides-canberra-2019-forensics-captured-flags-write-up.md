---
layout: post
title: "BSides Brisbane 2019 CTF - forensics - Captured Flags (500pts)"
description: "BSides Brisbane 2019 CTF - forensics - Captured Flags (500pts)"
category: ctf, bsides_brisbane_2019, forensics, wireshark, python, shellcode, write-up
tags: [ctf, bsides_brisbane_2019, forensics, wireshark, python, shellcode, write-up]
---


### Original description: ###
```text
Captured Flags (500pts)

Exactly what it says on the tin!

Files:
capturedflags.pcap
```

The attached capturedflags.pcap file is a packet capture of some web traffic.
The packet capture only contains one client(172.18.0.1) which sends a HTTP GET request to a web server at 172.18.0.1:9000. The web server returns a series of PNG images.

I initially tried using NetworkMiner to carve out the PNG files but it failed.
I was able to extract all of the HTTP traffic as hex using the following tshark command


#### Stage 1 ####
```shell
$ tshark -r capturedflags.pcap -Y 'http' -T fields -e data.data | tee  http.data
```

#### Stage 2 ####

With the extracted http responses, it's possible to carve out the PNG file by looking for the PNG magic bytes "89504e470d0a1a0a".
The following script will read in the extracted http requests, hex decode, extract the PNG and save it out as a file.
```python
#!/usr/bin/env python3
import re

for index, line in enumerate(open('http.data').readlines()):
    print('hex dump of http payload')
    data = line.strip().replace(':', '')
    print(data)
    png = bytes.fromhex(re.findall(r'.*(89504e470d0a1a0a.*)', data)[0])
    open(('%s.png' % index), 'wb').write(png)
```

The extracted PNG files is the flag encoded using flag semaphore.
Below is a sample PNG file that was extracted.

<img src="{{site.url}}/assets/2019-08-12-bsides-canberra-2019-forensics-captured-flags-0.png">


Decoding PNG files gives us: `THE FLAG IS CYBEARS BRACE ILOVEAGOODVISUALPUN BRACE`

The final flag is `CYBEARS{ILOVEAGOODVISUALPUN}`

#### References ####
https://en.wikipedia.org/wiki/Flag_semaphore