package curve25519

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSymmetricEncryption(t *testing.T) {
	key := GenerateSymmetricKey()
	nonce := GenerateNonce()
	m := Message([]byte{64, 136, 53, 44, 253, 57, 234, 186, 114, 18, 153, 65, 65, 192, 36,
		57, 161, 245, 97, 149, 79, 154, 111, 72, 195, 101, 225, 252, 115, 255, 141, 46, 101,
		117, 90, 158, 34, 143, 169, 134, 123, 204, 214, 189, 144, 87, 212, 255, 68, 245, 197,
		135, 130, 224, 14, 3, 122, 209, 108, 36, 103, 130, 107, 217, 170, 141, 236, 234, 223,
		222, 116, 182, 178, 119, 91, 193, 255, 248, 130, 162, 142, 255, 177, 46, 17, 11, 23,
		142, 30, 252, 192, 214, 106, 237, 225, 212, 145})
	c, err := SymmetricEncrypt(key, nonce, m)
	if err != nil {
		log.Fatal(err)
	}

	dec, err := SymmetricDecrypt(key, nonce, c)
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, m, dec, "Symmetric encryption and decryption are consistent")
}

func TestSymmetricDecryption(t *testing.T) {
	key1 := GenerateSymmetricKey()
	nonce1 := GenerateNonce()
	key2 := GenerateSymmetricKey()
	nonce2 := GenerateNonce()
	m := Message([]byte{64, 136, 53, 44, 253, 57, 234, 186, 114, 18, 153, 65, 65, 192, 36,
		57, 161, 245, 97, 149, 79, 154, 111, 72, 195, 101, 225, 252, 115, 255, 141, 46, 101,
		117, 90, 158, 34, 143, 169, 134, 123, 204, 214, 189, 144, 87, 212, 255, 68, 245, 197,
		135, 130, 224, 14, 3, 122, 209, 108, 36, 103, 130, 107, 217, 170, 141, 236, 234, 223,
		222, 116, 182, 178, 119, 91, 193, 255, 248, 130, 162, 142, 255, 177, 46, 17, 11, 23,
		142, 30, 252, 192, 214, 106, 237, 225, 212, 145})
	c, err := SymmetricEncrypt(key1, nonce1, m)
	if err != nil {
		log.Fatal(err)
	}

	_, err = SymmetricDecrypt(key2, nonce2, c)
	assert.Error(t, err, "Symmetric decryption errors with different key")

	// Modify ciphertext
	c[3] = 3

	_, err = SymmetricDecrypt(key1, nonce1, c)
	assert.Error(t, err, "Symmetric decryption errors with modified ciphertext")
}
