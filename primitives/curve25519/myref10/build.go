package myref10

// TODO FIXME: Hardcoding /usr/local/include is a bit dirty

// #cgo CFLAGS: -std=gnu11 -I/usr/local/include
// #cgo LDFLAGS: -L/usr/local/lib -lsodium
import "C"
