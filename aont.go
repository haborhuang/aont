// Package aont provides All-Or-Nothing Transform functionalities
package aont

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"unsafe"
)

const (
	k0Digit = byte(0x69)
)

// Encrypt transforms the plain data according to the specified cipher module
// and return the blocks.
func Encrypt(plain []byte, cm CipherModuler) ([][]byte, error) {
	blockSize := cm.GetBlockSize()
	keySize := cm.GetKeySize()

	// Generate random key
	key := make([]byte, keySize)
	rand.Read(key)
	// key := []byte(strings.Repeat("1", keySize))
	k0 := bytes.Repeat([]byte{k0Digit}, keySize)

	mCipher, err := cm.NewCipher(key)
	if nil != err {
		return nil, fmt.Errorf("New cipher handle for m'[i] error: %v", err)
	}
	hCipher, err := cm.NewCipher(k0)
	if nil != err {
		return nil, fmt.Errorf("New cipher handle for h[i] error: %v", err)
	}

	plainBytes, pNum := padding(plain, blockSize)

	var blocks [][]byte

	// s is number of plain blocks
	s := len(plainBytes) / blockSize
	hi := make([]byte, blockSize)

	// Last block is key xor h[1] xor h[2] ... xor h[s+1]
	lastBlockSize := blockSize
	if keySize > blockSize {
		lastBlockSize = keySize + blockSize - keySize%blockSize
	}
	lastBlock := make([]byte, lastBlockSize)
	xor(lastBlock, key)

	i := 1
	for ; i <= s; i++ {
		start := (i - 1) * blockSize
		mi := plainBytes[start : start+blockSize]

		mPrimeI := make([]byte, blockSize) // mPrimeI is m'[i]
		// m'[i] = Encrypt(key, i) xor m[i]
		mCipher.Encrypt(mPrimeI, intToBytes(i, blockSize))
		xor(mPrimeI, mi)
		blocks = append(blocks, mPrimeI)

		// h[i] = Encrypt(k0, m'[i] xor i) for i = 1, 2, ..., s, s+1
		hCipher.Encrypt(hi, xorWithInt(mPrimeI, i))
		xor(lastBlock, hi)
	}

	// mPrimeSPrime is m'[s'] where s' = s + 1
	// m'[s+1] = Encrypt(key, s+1) xor (padding count)
	mPrimeSPrime := make([]byte, blockSize)
	mCipher.Encrypt(mPrimeSPrime, intToBytes(i, blockSize))
	mPrimeSPrime = xorWithInt(mPrimeSPrime, pNum)
	blocks = append(blocks, mPrimeSPrime)

	// h[i] = Encrypt(k0, m'[i] xor i) for i = 1, 2, ..., s, s+1
	hCipher.Encrypt(hi, xorWithInt(mPrimeSPrime, i))
	xor(lastBlock, hi)

	blocks = append(blocks, lastBlock)

	return blocks, nil
}

// Decrypt returns the plain data inverted from blocks according to the
// specified cipher module.
func Decrypt(blocks [][]byte, cm CipherModuler) ([]byte, error) {
	if len(blocks) < 2 {
		return nil, fmt.Errorf("Invalid input")
	}

	blockSize := cm.GetBlockSize()
	keySize := cm.GetKeySize()

	k0 := bytes.Repeat([]byte{k0Digit}, keySize)
	hCipher, err := cm.NewCipher(k0)
	if nil != err {
		return nil, fmt.Errorf("New cipher handle for h[i] error: %v", err)
	}

	// Last block = key xor h[1] xor h[2] ... xor h[s+1],
	// so key = last block xor h[1] xor h[2] ... xor h[s+1]
	key := make([]byte, keySize)
	hi := make([]byte, blockSize)
	for i, mPrimeI := range blocks {
		if i == len(blocks)-1 {
			xor(key, mPrimeI)
		} else {
			// h[i] = Encrypt(k0, m'[i] xor i) for i = 1, 2, ..., s, s+1
			hCipher.Encrypt(hi, xorWithInt(mPrimeI, i+1))
			xor(key, hi)
		}
	}

	mCipher, err := cm.NewCipher(key)
	if nil != err {
		return nil, fmt.Errorf("New cipher handle for m'[i] error: %v", err)
	}

	var pNum int
	dataLen := blockSize * (len(blocks) - 2)
	// Alloc result whose capacity is a block size bigger than length,
	// so that there is enough space to calculate padding count.
	res := make([]byte, dataLen, dataLen+blockSize)
	for i, mPrimeI := range blocks {
		if i == len(blocks)-1 {
			break
		}

		start := i * blockSize
		mi := res[start : start+blockSize]

		// m'[i] = Encrypt(key, i) xor m[i],
		// so m[i] = m'[i] xor Encrypt(key, i)
		mCipher.Encrypt(mi, intToBytes(i+1, blockSize))
		xor(mi, mPrimeI)

		if i == len(blocks)-2 {
			// m'[s+1] = Encrypt(key, s+1) xor (padding count),
			// so padding count = m'[s+1] xor Encrypt(key, s+1)
			pNum = bytesToInt(mi)
		}
	}

	return res[:dataLen-pNum], nil
}

func bytesToInt(data []byte) int {
	var res, i int
	intSize := int(unsafe.Sizeof(i))
	if len(data) > intSize {
		i = len(data) - intSize
	}

	for ; i < len(data); i++ {
		res <<= 8
		res += int(0xff & data[i])
	}
	return res
}

// Padding blank char so that plain data length is integral multiple of blockSize
func padding(plain []byte, blockSize int) ([]byte, int) {
	pNum := blockSize - len(plain)%blockSize
	b := make([]byte, len(plain)+blockSize-len(plain)%blockSize)

	for i := range b {
		if i < len(plain) {
			b[i] = plain[i]
		} else {
			b[i] = ' '
		}
	}

	return b, pNum
}

func intToBytes(i int, size int) []byte {
	b := make([]byte, size)
	for j := size - 1; i > 0 && j >= 0; i >>= 8 {
		b[j] = byte(i & 0xff)
		j--
	}

	return b
}

// For each byte in 'src', compute exclusive-or with the byte in the same position of
// 'target', and save result in 'src'.
func xor(src, target []byte) {
	for i, j := len(src)-1, len(target)-1; i >= 0 && j >= 0; {
		src[i] ^= target[j]
		i--
		j--
	}
}

func xorWithInt(a []byte, i int) []byte {
	c := make([]byte, len(a))

	j := len(a) - 1
	for ; j >= 0 && i > 0; i >>= 8 {
		c[j] = byte(i) ^ a[j]
		j--
	}

	for k := 0; k <= j; k++ {
		c[k] = a[k]
	}

	return c
}
