package curve25519

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
	_ = [C.crypto_box_PUBLICKEYBYTES]byte(PublicKey{})
	_ = [C.crypto_box_SECRETKEYBYTES]byte(PrivateKey{})
	_ = [C.crypto_sign_PUBLICKEYBYTES]byte(PublicSignKey{})
	_ = [C.crypto_sign_SECRETKEYBYTES]byte(PrivateSignKey{})
}

// PublicKey is a public key used to decrypt
type PublicKey [32]byte

// PrivateKey is a secret key used to encrypt
type PrivateKey [32]byte

// PublicSignKey is a public key used to verify a digital signature
type PublicSignKey [32]byte

// PrivateSignKey is a secret key used to construct a digital signature
type PrivateSignKey [64]byte

// Message is the message to be signed or encrypted
type Message []byte

// Signature is the the output of signing a message with a private key
type Signature []byte

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

	result := C.crypto_box_seal_open(
		(*C.uchar)(&m[0]), (*C.uchar)(&c[0]), C.ulonglong(len(c)), (*C.uchar)(&pk[0]), (*C.uchar)(&sk[0]))
	if result != 0 {
		return Message(m), fmt.Errorf("failed to perform decryption: %d", result)
	}
	return Message(m), nil
}

// GenerateSignKeys outputs a public-private key pair
func GenerateSignKeys() (PublicSignKey, PrivateSignKey) {
	var psk PublicSignKey
	var ssk PrivateSignKey

	C.crypto_sign_keypair((*C.uchar)(&psk[0]), (*C.uchar)(&ssk[0]))
	return psk, ssk
}

// Sign uses the private key to sign a message
func Sign(ssk PrivateSignKey, m Message) (Signature, error) {
	sig := make([]byte, C.crypto_sign_BYTES)
	result := C.crypto_sign_detached((*C.uchar)(&sig[0]), nil, (*C.uchar)(&m[0]), C.ulonglong(len(m)), (*C.uchar)(&ssk[0]))
	if result != 0 {
		return Signature(sig), fmt.Errorf("failed to sign: %d", result)
	}
	return Signature(sig), nil
}

// Verify uses the public key to verify the message signature
func Verify(psk PublicSignKey, m Message, sig Signature) bool {
	result := C.crypto_sign_verify_detached(
		(*C.uchar)(&sig[0]), (*C.uchar)(&m[0]), C.ulonglong(len(m)), (*C.uchar)(&psk[0]))
	if result != 0 {
		fmt.Printf("%v", result)
		return false
	}
	return true
}

// SetupKeys creates n public-private key pairs encryption
func SetupKeys(n int) ([]PublicKey, []PrivateKey) {
	var pubKeys []PublicKey
	var privKeys []PrivateKey
	for i := 0; i < n; i++ {
		pk, sk := GenerateKeys()
		pubKeys = append(pubKeys, pk)
		privKeys = append(privKeys, sk)
	}

	return pubKeys, privKeys
}

// SetupSignKeys creates n public-private key pairs for signing
func SetupSignKeys(n int) ([]PublicSignKey, []PrivateSignKey) {
	var pubSignKeys []PublicSignKey
	var privSignKeys []PrivateSignKey
	for i := 0; i < n; i++ {
		psk, ssk := GenerateSignKeys()
		pubSignKeys = append(pubSignKeys, psk)
		privSignKeys = append(privSignKeys, ssk)
	}

	return pubSignKeys, privSignKeys
}
