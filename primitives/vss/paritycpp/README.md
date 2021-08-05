# Parity module

Used to compute the parity-check matrix of Shamir secret sharing.

It uses code from https://github.com/shaih/cpp-lwevss
wrapped using swig

It can also be compiled independently via cmake, just to simplify debugging of the C++ part.
But cmake is not used by Go.