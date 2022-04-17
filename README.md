PIN block library
=================

This project is an implementation of the ISO 9564-1:2017 PIN block formats. It
is intended to be shared by software projects that perform PIN processing
related to card payment processing.

Note that this is not intended to be a standalone project. It is intended to
be an object library that can be added to other projects as a submodule. The
object library has hidden symbol visibility such that it is not exposed as
part of the API of other projects.

Dependencies
------------

* C11 compiler such as GCC or Clang
* CMake
* OpenEMV common crypto abstraction

Usage
-----

This CMake project can be added to CMake parent projects using the CMake
`add_subdirectory()` command. An example of adding this project to a parent
project would be:
```
add_subdirectory(pinblock)
```

License
-------

Copyright (c) 2022 Leon Lynch.

This project is licensed under the terms of the LGPL v2.1 license. See LICENSE file.
