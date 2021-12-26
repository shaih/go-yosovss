package paritycpp

// TODO FIXME: Hardcoding /usr/local/include is abit dirty

// #cgo CXXFLAGS: -std=gnu++17 -I/usr/local/include
// #cgo LDFLAGS: -L/usr/local/lib -lntl -lgmp -lm
import "C"
