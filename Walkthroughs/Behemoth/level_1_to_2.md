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
we create a breakpoint at    0x080491b7 <+49>:	leave

we execute the program and counting 0x44 in decimal is 68 bytes so 68 bytes of buffer $ebp-0x44 + 4 bytes of $ebp + 4 bytes of return adress $ebp+4. all that gives us 76 bytes

we check the start of stack pointer $esp and $ebp 

```bash 
(gdb) break *0x080491b7
Breakpoint 1 at 0x80491b7
(gdb) run 
Starting program: /behemoth/behemoth1 
Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Password: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Authentication failure.
Sorry.

Breakpoint 1, 0x080491b7 in main ()
(gdb) x/25x $esp
0xffffd234:	0x41414100	0x41414141	0x41414141	0x41414141
0xffffd244:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd254:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd264:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd274:	0x41414141	0x41414141	0x41414141	0x00000041
0xffffd284:	0xffffd334	0xffffd33c	0xffffd2a0	0xf7fade34
0xffffd294:	0x0804909d
(gdb) x/25x $ebp
0xffffd278:	0x41414141	0x41414141	0x00000041	0xffffd334
0xffffd288:	0xffffd33c	0xffffd2a0	0xf7fade34	0x0804909d
0xffffd298:	0x00000001	0xffffd334	0xf7fade34	0xffffd33c
0xffffd2a8:	0xf7ffcb60	0x00000000	0xb00a04e2	0xfb97eef2
0xffffd2b8:	0x00000000	0x00000000	0x00000000	0xf7ffcb60
0xffffd2c8:	0x00000000	0xf99a1700	0xf7ffda20	0xf7da1c46
0xffffd2d8:	0xf7fade34
(gdb) x/25x $ebp-0x44
0xffffd234:	0x41414100	0x41414141	0x41414141	0x41414141
0xffffd244:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd254:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd264:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd274:	0x41414141	0x41414141	0x41414141	0x00000041
0xffffd284:	0xffffd334	0xffffd33c	0xffffd2a0	0xf7fade34
0xffffd294:	0x0804909d
```
we notice that it execeded $ebp+4 by one byte in  0xffffd278:	0x41414141	0x41414141	0x00000041 

and the start of stack at $esp 0xffffd234:	0x41414100	0x41414141 notice that 0x00 null byte is weird

i suspect that this is happening because of this line :    0x08049199 <+19>:	lea    -0x43(%ebp),%eax

it's loading 0x43 bytes instead of 0x44 so out next input will contain 75 bytes not 76 
## Debugging
in this phase i tried different approaches that i found online some weren't affective but it was a good +

this command will allow u to write a payload directly into memory
```bash
(gdb) set {char[75]}0xffffd234 = {0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45,0x45}
(gdb) x/20x $esp
0xffffd234:	0x45454545	0x45454545	0x45454545	0x45454545
0xffffd244:	0x45454545	0x45454545	0x45454545	0x45454545
0xffffd254:	0x45454545	0x45454545	0x45454545	0x45454545
0xffffd264:	0x45454545	0x45454545	0x45454545	0x45454545
0xffffd274:	0x45454545	0x45454545	0xf7454545	0x00000001
```

## Exploit

## Takeaways

## Additional notes

## Questions
