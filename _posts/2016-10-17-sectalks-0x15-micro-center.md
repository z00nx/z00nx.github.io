---
layout: post
title: "Sectalks 0x15 Micro Center write up"
description: "sectalks 0x14 Micro Center write up"
category: writeups
tags: [sectalks, ctf]
---

This CTF challenge was presented as a custom webstore web application. The web store takes a lot of influence from Mr Robot Season 2 Episode 10 in which Elliot visits Micro Center to buy a bunch of computer equipment.

This challenge consists of two parts:

* Gain access to web-store
* Buy all of the equipment

# Part 1
After connecting to the Sectalks VPN and browsing to the given URL, we see a pretty basic web store.

<img src="{{site.url}}/assets/micro-center-1.png">

A lot of the links on web store require you to be logged in to work with the exception of home, contact the admin and sign in pages. When you attempt to create an account it fails and the URL to create an account is returned.

<img src="{{site.url}}/assets/micro-center-2.png">

Testing the "Contact the Admin" feature reveals that it only accepts URLs for the site.

<img src="{{site.url}}/assets/micro-center-3.png">

Now that I have a URL which will create a user account and know that the admin only visit's links on the site, I can should be able to create an account.

First we submit submit the URL which will create an account into the "Contact the Admin" page. Since the URL which creates user accounts is a GET request, the admin should create an account by simply browsing to the URL.

<img src="{{site.url}}/assets/micro-center-4.png">

After submitting the URL we see that it was accepted.

<img src="{{site.url}}/assets/micro-center-5.png">

Finally we can confirm that the account was created by logging in

<img src="{{site.url}}/assets/micro-center-6.png">

If we browse to the products section we see the first flag

<img src="{{site.url}}/assets/micro-center-7.png">

The first flag is **FLAG{you_t0t4lly_just_w4tchdogg3d_th1s_store}**

# Part 2

The second half of the challenge is to buy all of the products listed in the products section.
The cost of all of the equipment is over 12000 E-coins but we only have 9999 E-coins so we have to earn more E-coin.
Not knowing how I was to earn more E-coin, I proceeded to play around with authenticated parts of the web store where I noticed something interesting.
The exchange section of the web store which allows us to exchange real money to E-coins and vice versa has a vulnerability.
The exchange function of the web store does not validate if the input provided is positive and if the you have enough funds for the currency exchange.

In the below screenshot, I started with 9999 E-coins.

<img src="{{site.url}}/assets/micro-center-8.png">

I submitted an exchange of -9990 from E-coins to real money and the exchange was accepted.

<img src="{{site.url}}/assets/micro-center-9.png">

I continued playing with the exchange and I found that the upper limit of the allowed exchange was around -99999999999999990.
By abusing this oversight, I was able to get enough E-coins to purchase all of the equipment.
After buying all of the items the second flag  **FLAG{Init_5_is_supposed_to_bring_color_and_sound_Instead_the_worlds_gray_and_quiet_3590cb8}** is revealed.

<img src="{{site.url}}/assets/micro-center-10.png">
