# go-yosovss
Go implementation of YOSO-style verifiable secret sharing

## Running the project
After cloning the project, clone the libsodium submodule
```
cd libsodium
git submodule init
git submodule update
```

For Mac and Unix-like systems, install libsodium by running in the libsodium folder
```
./configure
make && make check
sudo make install
```

For other systems, refer to https://doc.libsodium.org/installation

After building libsodium, ensure that in the `curve25519.go` file that the `#cgo` directives point to the correct location of the libsodium static library file.