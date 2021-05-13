package curve25519

// #include "sodium.h"
import "C"

import (
	"fmt"
	"log"
	"unsafe"
)

func init() {
	if C.sodium_init() < 0 {
		log.Fatal("failed to initialize libsodium")
	}

	// Check sizes of structs
	_ = [C.crypto_secretbox_KEYBYTES]byte(Key{})
	_ = [C.crypto_secretbox_NONCEBYTES]byte(Nonce{})
}

// Key is a key for symmetric encryption
type Key [32]byte

// Nonce is the nonce for symmetric encryption
type Nonce [24]byte

// KeyNoncePair is a pair of a key and nonce to use for encryption
type KeyNoncePair struct {
	Key   Key
	Nonce Nonce
}

// Ciphertext is the encryption of a message
type SymmetricCiphertext []byte

// GenerateSymmetricKey outputs a key for symmetric encryption
func GenerateSymmetricKey() Key {
	var key Key

	C.crypto_secretbox_keygen((*C.uchar)(&key[0]))
	return key
}

// GenerateNonce outputs a nonce for symmetric encryption
func GenerateNonce() Nonce {
	var nonce Nonce
	C.randombytes_buf(unsafe.Pointer(&nonce[0]), C.ulong(len(nonce)))
	return nonce
}

// SymmetricEncrypt uses a symmetric key and nonce to encrypt a message and produce the ciphertext
func SymmetricEncrypt(key Key, nonce Nonce, m Message) (SymmetricCiphertext, error) {
	c := make([]byte, len(m)+C.crypto_secretbox_MACBYTES)
	result := C.crypto_secretbox_easy((*C.uchar)(&c[0]), (*C.uchar)(&m[0]), C.ulonglong(len(m)), (*C.uchar)(&nonce[0]), (*C.uchar)(&key[0]))
	if result != 0 {
		return SymmetricCiphertext(c), fmt.Errorf("failed to perform symmetric encryption: %d", result)
	}
	return SymmetricCiphertext(c), nil
}

// SymmetricDecrypt uses the symmetric key and nonce to decrypt the ciphertext and produce the original message
func SymmetricDecrypt(key Key, nonce Nonce, c SymmetricCiphertext) (Message, error) {
	m := make([]byte, len(c)-C.crypto_box_MACBYTES)

	result := C.crypto_secretbox_open_easy((*C.uchar)(&m[0]), (*C.uchar)(&c[0]), C.ulonglong(len(c)), (*C.uchar)(&nonce[0]), (*C.uchar)(&key[0]))
	if result != 0 {
		return Message(m), fmt.Errorf("failed to perform symmetric decryption: %d", result)
	}
	return Message(m), nil
}
