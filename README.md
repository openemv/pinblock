PIN block library
=================

[![License: LGPL-2.1](https://img.shields.io/github/license/openemv/pinblock)](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html)

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
* [CMake](https://cmake.org/)
* [OpenEMV common crypto abstraction](https://github.com/openemv/crypto)
  (to be provided as CMake targets by parent project)

Usage
-----

This CMake project can be added to CMake parent projects using the CMake
`add_subdirectory()` command. When this project is added to a parent project,
the `test` subdirectory is not added automatically. Parent projects can add
the `test` subdirectory manually if the tests are of interest to the parent
project. However, note that the `test` subdirectory requires the CMake `CTest`
module and that the tests will only be built when the `BUILD_TESTING` option
is enabled (`CTest` enables it by default).

An example of adding this project to a parent project would be:
```
add_subdirectory(pinblock)
add_subdirectory(pinblock/test)
```

Roadmap
-------
* Consider implementing other proprietary PIN block formats like those of
  Docutel ATMs, Diebold/IBM ATMs, Mastercard PNPL, Visa PIN change, etc.

License
-------

Copyright 2022 [Leon Lynch](https://github.com/leonlynch).

This project is licensed under the terms of the LGPL v2.1 license. See LICENSE file.
