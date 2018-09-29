package aont

import (
	"crypto/aes"
	"crypto/cipher"
)

// CipherModuler is an interface to provide getters for block
// size and key size
type CipherModuler interface {
	GetBlockSize() int
	GetKeySize() int
	NewCipher(key []byte) (cipher.Block, error)
}

type aesCM struct {
	keySize int
}

// NewAESModuler returns a CipherModuler for AES-128
func NewAESModuler() *aesCM {
	return newAESCM(16)
}

// NewAES192Moduler returns a CipherModuler for AES-192
func NewAES192Moduler() *aesCM {
	return newAESCM(24)
}

// NewAES256Moduler returns a CipherModuler for AES-256
func NewAES256Moduler() *aesCM {
	return newAESCM(32)
}

func newAESCM(s int) *aesCM {
	return &aesCM{
		keySize: s,
	}
}

func (cm *aesCM) GetBlockSize() int {
	return aes.BlockSize
}

func (cm *aesCM) GetKeySize() int {
	return cm.keySize
}

func (cm *aesCM) NewCipher(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}
