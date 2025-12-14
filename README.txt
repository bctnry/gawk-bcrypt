bcrypt for gawk
===============

this repository contains the gawk extension that adds bcrypt.

this extension expect OpenWall's version of bcrypt and requires its
source code to build. despite it being in public domain, this repo
does not contain it for the reason that it's not my code.

-- z lin



how to use
-----------

1.  after cloning this repository, copy OpenWall's bcrypt
    implementation under this very directory. the files you'll need
	would be:

    + crypt.h
	+ crypt_blowfish.c
	+ crypt_blowfish.h
	+ crypt_gensalt.c
	+ crypt_gensalt.h
	+ ow-crypt.h
	+ wrapper.c
	+ x86.S

    you don't need the Makefile file it comes with, we have our own
    Makefile.

2.  run `make all`.

3.  after step 2 there should be a `bcrypt.so` file generated. this is
    the one you should have alongside w/ your awk scripts.

after `@load "bcrypt"`, the extension provide two functions:

+ `bcrypt::hash_with_salt([input], [salt_strength])`
  hashes `[input]` w/ the specified salt strength. `[input]` should be
  a string and `[salt_strength]` should be a number. since awk does
  implicit conversion you technically *can* pass in certain wrong types,
  but i don't guarantee its behaviour.

+ `bcrypt::check_hash([key], [hash])`
  check if `[key]` is the same as the key used to produce `[hash]`.



