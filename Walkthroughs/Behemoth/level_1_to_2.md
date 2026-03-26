# Behemoth Level 1 → 2
## Note

This is not a straight-to-the-point solution.  
It documents the full thought process, including failed attempts and debugging, to focus on understanding rather than just solving.

## Overview

## Initial Analysis
when executing './behemoth1' u see that it asks for a password.

using ltrace to track library calls and find out more
```bash
behemoth1@behemoth:/behemoth$ ltrace ./behemoth1
__libc_start_main(0x804909d, 1, 0xffffd364, 0 <unfinished ...>
printf("Password: ")                                                                                                           = 10
gets(0xffffd265, 0xf7fc7000, 0, 0Password: test
)                                                                                             = 0xffffd265
puts("Authentication failure.\nSorry."Authentication failure.
Sorry.
)                                                                                        = 31
+++ exited (status 0) +++
```
we notice that it calls a gets function and its giving us the adress for where the start of our input through gets().

its not calling any other functions as strcpy()

using strings to get some more data about it
```bash
behemoth1@behemoth:/behemoth$ strings behemoth1
td4 
/lib/ld-linux.so.2
_IO_stdin_used
puts
gets
__libc_start_main
printf
libc.so.6
GLIBC_2.0
GLIBC_2.34
__gmon_start__
Password: 
Authentication failure.
Sorry.
;*2$"
GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0
crt1.o
```
all the functions used in the program should be mentioned just like puts gets printf 

so the program is not trying any comparaison, any password you enter will give the same output

executing the binary to notice what happens when entering a large value

```bash
behemoth1@behemoth:/behemoth $./behemoth1
Password: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Authentication failure.
Sorry.
Segmentation fault (core dumped)
```
segmentation fault could suggest that the return adress is being overwritten

## Vulnerability

## First Attempts

## Debugging

## Exploit

## Takeaways

## Additional notes

## Questions
