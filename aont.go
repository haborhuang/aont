// Package aont provides All-Or-Nothing Transform functionalities
package aont

import (
	"bytes"
	"fmt"
	"math/rand"
	"runtime"
	"time"
	"unsafe"
)

const (
	k0Digit = byte(0x69)
)

// Encrypt transforms the plain data according to the specified cipher module
// and returns the blocks.
func Encrypt(plain []byte, cm CipherModuler) ([][]byte, error) {
	blockSize := cm.GetBlockSize()
	enc, err := EncryptToBytes(plain, cm)
	if nil != err {
		return nil, err
	}

	s := plainBlocksCount(len(plain), blockSize)
	blocks := make([][]byte, 0, s+2)
	i := 0
	start := i * blockSize
	for i <= s {
		blocks = append(blocks, enc[start:start+blockSize])
		i++
		start = i * blockSize
	}
	blocks = append(blocks, enc[start:])

	return blocks, nil
}

// EncryptToBytes does the same thing as Encrypt but the blocks are returned in bytes.
func EncryptToBytes(plain []byte, cm CipherModuler) ([]byte, error) {
	blockSize := cm.GetBlockSize()
	keySize := cm.GetKeySize()

	k0 := bytes.Repeat([]byte{k0Digit}, keySize)
	// Generate random key
	key := make([]byte, keySize)
	genRandKey(key)
	// key = []byte(strings.Repeat("1", keySize)) // Enable this to transform with fixed key to debug

	mCipher, err := cm.NewCipher(key)
	if nil != err {
		return nil, fmt.Errorf("New cipher handle for m'[i] error: %v", err)
	}
	hCipher, err := cm.NewCipher(k0)
	if nil != err {
		return nil, fmt.Errorf("New cipher handle for h[i] error: %v", err)
	}

	pNum := blockSize - len(plain)%blockSize // Padding count
	plainLen := len(plain) + pNum

	// s is number of plain blocks
	s := plainBlocksCount(len(plain), blockSize)
	hi := make([]byte, blockSize)

	// Last block is key xor h[1] xor h[2] ... xor h[s+1]
	lbSize := lastBlockSize(blockSize, keySize)
	// Pre-alloc m' rather than to alloc each m'[i] to reduce stress of GC
	mPrime := make([]byte, plainLen+blockSize+lbSize)
	lastBlock := mPrime[len(mPrime)-lbSize:]
	xor(lastBlock, key)

	i := 1
	start := (i - 1) * blockSize
	// tmp is temporary buffer to save result of xorWithInt and intToBytes functions
	tmp := make([]byte, blockSize)
	// bytesI is temporary buffer to save i in bytes
	bytesI := make([]byte, blockSize)
	var mi []byte
	for ; i <= s; i++ {
		if start+blockSize > len(plain) {
			// i.e. start+blockSize == len(plain) + pNum and padding is needed.
			mi = make([]byte, 0, blockSize)   // Alloc a slice to avoid changing 'plain'
			mi = append(mi, plain[start:]...) // Copy data from 'plain'
			for j := 0; j < pNum; j++ {
				mi = append(mi, ' ') // Pad with blank
			}
		} else {
			mi = plain[start : start+blockSize]
		}
		mPrimeI := mPrime[start : start+blockSize] // mPrimeI is m'[i]
		// m'[i] = Encrypt(key, i) xor m[i]
		// intToBytes(tmp, i)
		// mCipher.Encrypt(mPrimeI, tmp)
		bytesPP(bytesI)
		mCipher.Encrypt(mPrimeI, bytesI)
		xor(mPrimeI, mi)

		// h[i] = Encrypt(k0, m'[i] xor i) for i = 1, 2, ..., s, s+1
		xorWithInt(tmp, mPrimeI, i)
		hCipher.Encrypt(hi, tmp)
		xor(lastBlock, hi)
		start = i * blockSize
	}

	// mPrimeSPrime is m'[s'] where s' = s + 1
	// m'[s+1] = Encrypt(key, s+1) xor (padding count)
	mPrimeSPrime := mPrime[start : start+blockSize]
	// intToBytes(tmp, i)
	// mCipher.Encrypt(mPrimeSPrime, tmp)
	bytesPP(bytesI)
	mCipher.Encrypt(mPrimeSPrime, bytesI)
	xorWithInt(mPrimeSPrime, mPrimeSPrime, pNum)

	// h[i] = Encrypt(k0, m'[i] xor i) for i = 1, 2, ..., s, s+1
	xorWithInt(tmp, mPrimeSPrime, i)
	hCipher.Encrypt(hi, tmp)
	xor(lastBlock, hi)

	return mPrime, nil
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
	// tmp is temporary buffer to save result of xorWithInt and intToBytes functions
	tmp := make([]byte, blockSize)
	for i, mPrimeI := range blocks {
		if i == len(blocks)-1 {
			xor(key, mPrimeI)
		} else {
			// h[i] = Encrypt(k0, m'[i] xor i) for i = 1, 2, ..., s, s+1
			xorWithInt(tmp, mPrimeI, i+1)
			hCipher.Encrypt(hi, tmp)
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
	// bytesI is temporary buffer to save i in bytes
	bytesI := make([]byte, blockSize)
	for i, mPrimeI := range blocks {
		if i == len(blocks)-1 {
			break
		}

		start := i * blockSize
		mi := res[start : start+blockSize]

		// m'[i] = Encrypt(key, i) xor m[i],
		// so m[i] = m'[i] xor Encrypt(key, i)
		// intToBytes(tmp, i+1)
		// mCipher.Encrypt(mi, tmp)
		bytesPP(bytesI)
		mCipher.Encrypt(mi, bytesI)
		xor(mi, mPrimeI)

		if i == len(blocks)-2 {
			// m'[s+1] = Encrypt(key, s+1) xor (padding count),
			// so padding count = m'[s+1] xor Encrypt(key, s+1)
			pNum = bytesToInt(mi)
		}
	}

	return res[:dataLen-pNum], nil
}

// DecryptFromBytes does the same thing as Decrypt but blocks are specified in bytes.
func DecryptFromBytes(data []byte, cm CipherModuler) ([]byte, error) {
	blockSize := cm.GetBlockSize()
	keySize := cm.GetKeySize()
	lbSize := lastBlockSize(blockSize, keySize)
	if len(data) < blockSize+lbSize {
		return nil, fmt.Errorf("Invalid input")
	}
	blocksCount := (len(data)-lbSize)/blockSize + 1

	blocks := make([][]byte, 0, blocksCount)
	for i := 0; i < blocksCount; i++ {
		start := i * blockSize
		end := start + blockSize
		if i == blocksCount-1 {
			end = len(data)
		}
		blocks = append(blocks, data[start:end])
	}

	return Decrypt(blocks, cm)
}

func plainBlocksCount(plainSize, blockSize int) int {
	return (plainSize + blockSize - 1) / blockSize
}

func lastBlockSize(blockSize, keySize int) int {
	s := blockSize
	if keySize > s {
		s = keySize
	}
	return s
}

const intSize = int(unsafe.Sizeof(int(0)))

func bytesToInt(data []byte) int {
	var res, i int
	if len(data) > intSize {
		i = len(data) - intSize
	}

	for ; i < len(data); i++ {
		res <<= 8
		res += int(0xff & data[i])
	}
	return res
}

func intToBytes(dst []byte, i int) {
	j := len(dst) - 1
	for ; i > 0 && j >= 0; i >>= 8 {
		dst[j] = byte(i & 0xff)
		j--
	}

	for ; j >= 0; j-- {
		dst[j] = 0
	}
}

// ++ Operation for bytes
func bytesPP(b []byte) {
	if len(b) == 0 {
		return
	}

	if b[len(b)-1] == 0xff {
		b[len(b)-1] = 0
		bytesPP(b[:len(b)-1])
	} else {
		b[len(b)-1]++
	}
}

// For each byte in 'dst', compute exclusive-or with the byte in the same position
// in the reverse order of 'src', and save result as 'dst'.
func xor(dst, src []byte) {
	if supportsUnaligned {
		fastXOR(dst, src)
	} else {
		for i := 1; i <= len(dst) && i <= len(src); i++ {
			dst[len(dst)-i] ^= src[len(src)-i]
		}
	}
}

// Calculate exclusive-or of src and i, save the result as dst
func xorWithInt(dst []byte, src []byte, i int) {
	j := len(src) - 1
	for ; j >= 0 && i > 0; i >>= 8 {
		dst[j] = byte(i) ^ src[j]
		j--
	}

	for k := 0; k <= j; k++ {
		dst[k] = src[k]
	}
}

var randSrc = rand.NewSource(time.Now().UnixNano())

func genRandKey(key []byte) {
	// Generate 63 random bits
	var rn int64
	for i := range key {
		if i%8 == 0 {
			rn = randSrc.Int63()
		}
		key[i] = byte(0xff & rn)
		rn >>= 8
	}
}

const wordSize = int(unsafe.Sizeof(uintptr(0)))
const supportsUnaligned = runtime.GOARCH == "386" || runtime.GOARCH == "amd64" || runtime.GOARCH == "ppc64" || runtime.GOARCH == "ppc64le" || runtime.GOARCH == "s390x"

// This function refers to src/crypto/cipher/xor.go of Golang
func fastXOR(dst, src []byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	if n == 0 {
		return
	}

	dst = dst[len(dst)-n:]
	src = src[len(src)-n:]

	w := n / wordSize
	if w > 0 {
		dw := *(*[]uintptr)(unsafe.Pointer(&dst))
		sw := *(*[]uintptr)(unsafe.Pointer(&src))

		for i := 0; i < w; i++ {
			dw[i] ^= sw[i]
		}
	}
	for i := (n - n%wordSize); i < n; i++ {
		dst[i] ^= src[i]
	}
}
