dovecot_encrypt
===============

Dovecot 2.x transparent encryption plugin



Dovecot encrypt plugin is based on a zlib module that was written for Dovecot. Zlib module in its turn is more or less a storage plugin.

At the moment this plugin is in a very alpha stage, but proven to be working for simple setups. There are a few dozens of places in codes that are marked with XXX which needs fixation before I can consider changing the status of the plugin from alpha to at least beta.

Please be informed that I am not a professional programmed and I program for fun, not for profit. Although interesting proposals are likely to be considered.



This time, no separate TODO list will be created due to the fact that the TODO list is not yet formed completely. Therefore, I am inlining TODO list here temporarily:


1. Get rid of XXX comments in the code.
2. Add a database support for storing and retrieving  RSA keys.
3. Add support for different encryption algorithms. Right now only RSA is implemented.
4. Create minimal and working Makefile.
5. Document the code thoroughly so that next time I reread portions of code and actually DO understand what it does.
6. Write tests.



