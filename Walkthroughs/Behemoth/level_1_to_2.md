# Behemoth Level 1 → 2
## Note
This walkthrough is based on challenges from [OverTheWire](https://overthewire.org).

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

another analysis we can run with gdb 

```bash
gdb ./behemoth1
```
here we see what functions are in the program and the dissambling of main 

```bash
(gdb) info func
All defined functions:

Non-debugging symbols:
0x08049000  _init
0x08049030  __libc_start_main@plt
0x08049040  printf@plt
0x08049050  gets@plt
0x08049060  puts@plt
0x08049070  _start
0x0804909d  __wrap_main
0x080490b0  _dl_relocate_static_pie
0x080490c0  __x86.get_pc_thunk.bx
0x080490d0  deregister_tm_clones
0x08049110  register_tm_clones
0x08049150  __do_global_dtors_aux
0x08049180  frame_dummy
0x08049186  main
0x080491bc  _fini
```
```bash
(gdb) disassemble main
Dump of assembler code for function main:
   0x08049186 <+0>:	push   %ebp
   0x08049187 <+1>:	mov    %esp,%ebp
   0x08049189 <+3>:	sub    $0x44,%esp
   0x0804918c <+6>:	push   $0x804a008
   0x08049191 <+11>:	call   0x8049040 <printf@plt>
   0x08049196 <+16>:	add    $0x4,%esp
   0x08049199 <+19>:	lea    -0x43(%ebp),%eax
   0x0804919c <+22>:	push   %eax
   0x0804919d <+23>:	call   0x8049050 <gets@plt>
   0x080491a2 <+28>:	add    $0x4,%esp
   0x080491a5 <+31>:	push   $0x804a014
   0x080491aa <+36>:	call   0x8049060 <puts@plt>
   0x080491af <+41>:	add    $0x4,%esp
   0x080491b2 <+44>:	mov    $0x0,%eax
   0x080491b7 <+49>:	leave
   0x080491b8 <+50>:	ret
End of assembler dump.
```
0x08049189 <+3>:	sub    $0x44,%esp : this line is allocating a buffer with a size of 0x44

## Vulnerability
the vulnerability here is in the gets() function, it doesn't check the buffer size and allows a buffer overflow which would allow overwriting the return adress 

you can read more about it in https://cwe.mitre.org/data/definitions/242.html
## First Attempts

## Debugging

## Exploit

## Takeaways

## Additional notes

## Questions
