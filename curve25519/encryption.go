package curve25519

// #cgo CFLAGS: -Wall -std=c99
// #cgo LDFLAGS: -lsodium
// #include <stdint.h>
// #include "sodium.h"
import "C"

import (
	"fmt"
	"log"
)

func init() {
	if C.sodium_init() < 0 {
		log.Fatal("failed to initialize libsodium")
	}

	// Check sizes of structs
	_ = [C.crypto_core_ed25519_BYTES]byte(Point{})
	_ = [C.crypto_core_ed25519_SCALARBYTES]byte(Scalar{})
	_ = [C.crypto_box_PUBLICKEYBYTES]byte(PublicKey{})
	_ = [C.crypto_box_SECRETKEYBYTES]byte(PrivateKey{})
}

// Message is the message to be signed or encrypted
type Message []byte

// Ciphertext is the encryption of a message
type Ciphertext []byte

// GenerateKeys outputs a public-private key pair
func GenerateKeys() (PublicKey, PrivateKey) {
	var pk PublicKey
	var sk PrivateKey

	C.crypto_box_keypair((*C.uchar)(&pk[0]), (*C.uchar)(&sk[0]))
	return pk, sk
}

// Encrypt uses a public key to encrypt a message and produce the ciphertext
func Encrypt(pk PublicKey, m Message) (Ciphertext, error) {
	c := make([]byte, len(m)+C.crypto_box_SEALBYTES)

	result := C.crypto_box_seal((*C.uchar)(&c[0]), (*C.uchar)(&m[0]), C.ulonglong(len(m)), (*C.uchar)(&pk[0]))
	if result != 0 {
		return Ciphertext(c), fmt.Errorf("failed to perform encryption: %d", result)
	}
	return Ciphertext(c), nil
}

// Decrypt uses the private key to decrypt the ciphertext and produce a message
func Decrypt(pk PublicKey, sk PrivateKey, c Ciphertext) (Message, error) {
	m := make([]byte, len(c)-C.crypto_box_SEALBYTES)

	result := C.crypto_box_seal_open((*C.uchar)(&m[0]), (*C.uchar)(&c[0]), C.ulonglong(len(c)), (*C.uchar)(&pk[0]), (*C.uchar)(&sk[0]))
	if result != 0 {
		return Message(m), fmt.Errorf("failed to perform decryption: %d", result)
	}
	return Message(m), nil
}
