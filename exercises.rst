===============
Ropeme exercise
===============

Introduction
============

The following exercises are meant to be used in conjonction with ropeme to
learn the basics of binary exploitation. In each case a hint is provided in
base64 to avoid unwanted spoiler, but you should be able to do it without.

Although the exercises are meant to be solved in a specific way, feel free to
be creative in your solution: this is all about hacking after all :)

The first three exercises are general reminders, the rest is more precisely
targetted at ROP.

Exercise 1
==========

Find the user name.

TG9vayBmb3Igc3RyaW5ncwo=

Exercise 2
==========

Find the password.

SSB3aXNoIEkgY291bGQgc2VlIHdoYXQgdGhlIGlucHV0IGlzIGNvbXBhcmVkIHRvLi4uCg==

Exercise 3
==========

Print the winning message without the right password.

SG93IGJpZyBpcyB0aGF0IGJ1ZmZlciBhZ2Fpbj8K

Exercise 4
==========

Describe what happens when a function calls a sub-routine.
What is the top of the stack like before a call to puts? To strcmp?

aHR0cDovL3d3dy5jc2VlLnVtYmMuZWR1L35jaGFuZy9jczMxMy5zMDIvc3RhY2suc2h0bWwK

Exercise 5
==========

Controlling the stack, display the password instead of executing the whole
program.

VXNpbmcgYSBidWZmZXIgb3ZlcmZsb3cgeW91IGNhbiBvdmVyd3JpdGUgdGhlIGNvbnRlbnQgb2Yg
dGhlIHN0YWNrLCBidXQgdGhlIHN0YWNrIGRlc2NyaWJlcyB3aGF0IGZ1bmN0aW9ucyBhcmUgYmVp
bmcgY2FsbGVkLi4uIFdoYXQgYWJvdXQgc2V0dGluZyB5b3VyIG93biBmdW5jdGlvbnMgYW5kIGFy
Z3VtZW50cz8K

Exercise 6
==========

Using a similar technique, display a message of your choice.

QW55IGlucHV0IHNob3VsZCBhdCBvbmUgdGltZSBvciB0aGUgb3RoZXIgZ28gdGhyb3VnaCB0aGUg
cmVhZCBzeXN0ZW0gY2FsbCwgc2hvdWxkbid0IGl0Pwo=

Exercise 7
==========

Display the address of the dynamically linked `puts` libc function.

WW91IG1heSB3YW50IHRvIHJlYWQgYWJvdXQgdGhlIFBMVCBhbmQgdGhlIEdPVCBpZiB0aGVzZSBj
b25jZXB0cyBhcmVuJ3QgY3Jpc3RhbCBjbGVhcjoKaHR0cHM6Ly93d3cudGVjaG5vdmVsdHkub3Jn
L2xpbnV4L3BsdC1hbmQtZ290LXRoZS1rZXktdG8tY29kZS1zaGFyaW5nLWFuZC1keW5hbWljLWxp
YnJhcmllcy5odG1sCg==

Exercise 8
==========

Display the address of the `system` libc function.

VGhlIG9mZnNldCBpcyBjb25zdGFudAo=

Exercise 9
==========

Get a shell by combining what has been done.

bWFuIDMgc3lzdGVtIDpwCg=
