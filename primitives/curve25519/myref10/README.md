# Myref10

Myref10 is the C implementation of the functions we need for elliptic curve operations and field operations 
that are not missing from libsodium.

This includes multi-scalar-multiplication for example, or matrix multiplication of scalars.

This folder comes partially from libsodium 1.0.18 ZIP (https://github.com/jedisct1/libsodium/releases)
after doing `./configure`

This is very dirty.
It may not work properly.
A cleaner solution would have been to properly fork libsodium but this is then more complex for the compilation

Note: The code is not very clean with a lot of copy-pasting. Production code requires a lot of cleaning.

## How to use it

If the only goal is to use the Go program, there is no need to do anything.
Go will automatically compile everything needed via CGO.

However, for test of just this C library (e.g., for debugging), `cmake` can be used.
For example:
```bash
make cmake-build
cd cmake-build
cmake -DCMAKE_BUILD_TYPE=Debug ..
```

This is *NOT* used by Go.

If there are any dependency issues in Go, check flags on top of `build.go`.

## How the second base (base h) was generated

Using the script `ref10/fe25_5/base_h.py`
