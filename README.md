Support code for simple NTS client implementation
=================================================

To build, simply run `make`, then run `./demo`, or `./demo [timeserver]`. This performs a NTS handshake and query the underlying NTP server once. It is also possible to select a certain AEAD algorithm by using `./demo [timeserver] [AEAD]`.

Overview
--------

### Demonstration programs
* `demo.c`: Demonstrator for SSL handshake + NTP query
* `sntp.c`: SNTP client code
* `qdntp.c`: CLI wrapper for `sntp.c` (does NTP query only)

These all handle errors using `assert`, i.e. are not meant for inclusion in production code but are good enough as demonstrators.

### NTS Implementation
* `nts_packet.c`: code for encoding/decoding NTS packets according to RFC8915
* `nts_extfields.c`: code for encoding/decoding NTS extension fields according to RFC8915, RFC5905, RFC7822 and so on
* `nts_ssl.c`: code for handling TLS objects in the context of NTS (setup for handshake, key extraction, cipher selection)

### Support code
* `tcp_connect.c`: connects/associates a socket to/with a TCP/UDP host

This is shared between `qdntp` and `nts_ssl.c`.

### Test code
* `nts_test.c`: Several unit tests for packet encoding/decoding
* `nts_fuzz.c`: Code for fuzzing packet decoding.

These perform less error checking since they are meant for execution with ASan and UBsan enabled.

Testing
-------
Run unit tests:
```
CC="cc -fsanitize=address,undefined" make -B test
```

To run fuzz tests, make sure you have `afl++` installed:
```
CC="afl-clang -fsanitize=address,integer,undefined" make -B fuzz_ntp
```
and
```
CC="afl-clang -fsanitize=address,integer,undefined" make -B fuzz_ntske
```

Legal
-----
Copyright (C) 2025, Trifecta Tech Foundation

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; see the file LICENSE.
