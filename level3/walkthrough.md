# Level 3

## Setup
We find a binary file at the root of the user **`level3`** named *`./level3`*.

To analyze the binary file we copy it to our own environment with `scp` *(OpenSSH secure file copy)*.
```bash
scp -r -P 4243 level3@localhost:/home/user/level3/level3 .
```

### Radare2

I am running `r2` inside docker.
```bash
docker run -it -v "$bin_file_path":/mnt/binary radare/radare2 bash -c "r2 /mnt/binary"
```

## Binary Analysis

On the `r2` prompt we need to run a couple of commands to analyze the `main` function.
```bash
[0x08048de8]> aaa # Automatically analyze the binary
...
[0x08048ec0]> V # Enter visual mode
```

<p align="center">
  <img src = "../docs/level3.r2.png" width = "100%"> 
</p>

### Code with addresses
```assembly
0x080484A4 ; =============== S U B R O U T I N E =======================================
0x080484A4
0x080484A4 ; Attributes: bp-based frame
0x080484A4
0x080484A4 public v
0x080484A4 v proc near                             ; CODE XREF: main+6↓p
0x080484A4
0x080484A4 var_208= byte ptr -208h
0x080484A4
0x080484A4 ; __unwind {
0x080484A4 push    ebp
0x080484A5 mov     ebp, esp
0x080484A7 sub     esp, 218h
0x080484AD mov     eax, ds:stdin@@GLIBC_2_0
0x080484B2 mov     [esp+8], eax
0x080484B6 mov     dword ptr [esp+4], 200h
0x080484BE lea     eax, [ebp+var_208]
0x080484C4 mov     [esp], eax
0x080484C7 call    _fgets
0x080484CC lea     eax, [ebp+var_208]
0x080484D2 mov     [esp], eax
0x080484D5 call    _printf
0x080484DA mov     eax, ds:m
0x080484DF cmp     eax, 40h ; '@'
0x080484E2 jnz     short locret_8048518
0x080484E4 mov     eax, ds:stdout@@GLIBC_2_0
0x080484E9 mov     edx, eax
0x080484EB mov     eax, offset aWaitWhat           ; "Wait what?!\n"
0x080484F0 mov     [esp+0Ch], edx
0x080484F4 mov     dword ptr [esp+8], 0Ch
0x080484FC mov     dword ptr [esp+4], 1
0x08048504 mov     [esp], eax
0x08048507 call    _fwrite
0x0804850C mov     dword ptr [esp], offset aBinSh  ; "/bin/sh"
0x08048513 call    _system
0x08048518
0x08048518 locret_8048518:                         ; CODE XREF: v+3E↑j
0x08048518 leave
0x08048519 retn
0x08048519 ; } // starts at 80484A4
0x08048519 v endp
0x08048519
0x0804851A
0x0804851A ; =============== S U B R O U T I N E =======================================
0x0804851A
0x0804851A ; Attributes: bp-based frame fuzzy-sp
0x0804851A
0x0804851A ; int __cdecl main(int argc, const char **argv, const char **envp)
0x0804851A public main
0x0804851A main proc near                          ; DATA XREF: _start+17↑o
0x0804851A
0x0804851A argc= dword ptr  8
0x0804851A argv= dword ptr  0Ch
0x0804851A envp= dword ptr  10h
0x0804851A
0x0804851A ; __unwind {
0x0804851A push    ebp
0x0804851B mov     ebp, esp
0x0804851D and     esp, 0FFFFFFF0h
0x08048520 call    v
0x08048525 leave
0x08048526 retn
0x08048526 ; } // starts at 804851A
0x08048526 main endp
0x08048526
```

<p align="center">
  <img src = "../docs/level3.ida.png" width = "100%"> 
</p>

### Source

The equivalent program in C would be:
```C
#include <stdio.h>

int m = 0;

int v() {
    int result;         // EAX
    char buffer[520];   // [esp+10h] [ebp-208h] BYREF
    fgets(buffer, 512, stdin);  // Read up to 512 characters from stdin
    printf("%s", buffer); // Print the buffer
    result = m;
    if (m == '@') {
        fwrite("Wait what?!\n", 1, 12, stdout);
        return (system("/bin/sh"));
    }
    return (result);
}

int main() {
    return (v());
}
```

We can see that this time we have, an `fgets()` function instead of a `gets()` function. And also a global variable `m`, which is what determines if we can access the `system("/bin/sh")`.


### Permissions
As we can see in the permissions of the executable file, the binary `./level3` is executed with the privileges of the user **level4**, the owner of the file.
```bash
level3@RainFall:~$ ls -l level3 
-rwsr-s---+ 1 level4 users 5366 Mar  6  2016 level3
```

## Reverse Engineer

Our input captured by the `gets` function call, is on the `EAX` register (at the address `0xbffff5fc`), we can see it if we set a `breakpoint` after the `gets` call on `0x080484F2`.
Then the `EAX` register gets overwritten by `EBP + 4` with the instruction `mov eax, [ebp+4]`. 
Inside `EBP + 4` (at the address `0xbffff64c`) is the `main`'s `return` address (`0x0804854A`).
```bash
(gdb) set disassembly-flavor intel
(gdb) disassemble v
Dump of assembler code for function v:
   0x080484a4 <+0>:	push   ebp
   0x080484a5 <+1>:	mov    ebp,esp
   0x080484a7 <+3>:	sub    esp,0x218
   0x080484ad <+9>:	mov    eax,ds:0x8049860
   0x080484b2 <+14>:	mov    DWORD PTR [esp+0x8],eax
   0x080484b6 <+18>:	mov    DWORD PTR [esp+0x4],0x200
   0x080484be <+26>:	lea    eax,[ebp-0x208]
   0x080484c4 <+32>:	mov    DWORD PTR [esp],eax
   0x080484c7 <+35>:	call   0x80483a0 <fgets@plt>
   0x080484cc <+40>:	lea    eax,[ebp-0x208]
   0x080484d2 <+46>:	mov    DWORD PTR [esp],eax
   0x080484d5 <+49>:	call   0x8048390 <printf@plt>
   0x080484da <+54>:	mov    eax,ds:0x804988c
   0x080484df <+59>:	cmp    eax,0x40
   0x080484e2 <+62>:	jne    0x8048518 <v+116>
   0x080484e4 <+64>:	mov    eax,ds:0x8049880
   0x080484e9 <+69>:	mov    edx,eax
   0x080484eb <+71>:	mov    eax,0x8048600
   0x080484f0 <+76>:	mov    DWORD PTR [esp+0xc],edx
   0x080484f4 <+80>:	mov    DWORD PTR [esp+0x8],0xc
   0x080484fc <+88>:	mov    DWORD PTR [esp+0x4],0x1
   0x08048504 <+96>:	mov    DWORD PTR [esp],eax
   0x08048507 <+99>:	call   0x80483b0 <fwrite@plt>
   0x0804850c <+104>:	mov    DWORD PTR [esp],0x804860d
   0x08048513 <+111>:	call   0x80483c0 <system@plt>
   0x08048518 <+116>:	leave  
   0x08048519 <+117>:	ret    
End of assembler dump.
```

### Solution

We can execute the buffer overflow with this line. Of course, because we are running a shell through a pipe, we can keep the `stdin` open like the same trick from the last level:
```bash
$

cat /home/user/level4/.pass
492deb0e714c-------------------------------a521a4d33ec02
```