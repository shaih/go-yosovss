Adding required features.
Folder comes partly from libsodium ZIP
`./configure`

This is very dirty.
It may not work properly.
A cleaner solution would have been to properly fork libsodium.

It can also be compiled independently via cmake, just to simplify debugging of the C part.
But cmake is not used by Go.