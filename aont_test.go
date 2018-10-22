package aont

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
)

var testData = `This file implements all-or-nothing package transformations.

An all-or-nothing package transformation is one in which some text is
transformed into message blocks, such that all blocks must be obtained before
the reverse transformation can be applied.  Thus, if any blocks are corrupted
or lost, the original message cannot be reproduced.

An all-or-nothing package transformation is not encryption, although a block
cipher algorithm is used.  The encryption key is randomly generated and is
extractable from the message blocks.

This class implements the All-Or-Nothing package transformation algorithm
described in:

Ronald L. Rivest.  "All-Or-Nothing Encryption and The Package Transform"
http://theory.lcs.mit.edu/~rivest/fusion.pdf

`

func TestEncrypt(t *testing.T) {
	blocks, _ := Encrypt([]byte(testData), NewAESModuler())
	for i, b := range blocks {
		t.Log(i, base64.StdEncoding.EncodeToString(b))
	}
}

func TestMatch(t *testing.T) {
	cms := []CipherModuler{
		NewAESModuler(),
		NewAES192Moduler(),
		NewAES256Moduler(),
	}
	for i, cm := range cms {
		t.Log("Matching moduler", i)
		data := []byte(testData)
		blocks, _ := Encrypt(data, cm)
		encBytes := make([]byte, EncLen(len(data), cm))
		EncryptToBytes(encBytes, data, cm)

		got, _ := Decrypt(blocks, cm)
		if testData != string(got) {
			t.Fatal("Fail to match, decrypted:", got)
		}

		got = make([]byte, DecLen(len(encBytes), cm))
		size, _ := DecryptFromBytes(got, encBytes, cm)
		if testData != string(got[:size]) {
			t.Fatal("Fail to match the result decrypted from bytes, decrypted:", got)
		}
		t.Log("Matched")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	data := []byte(testData)
	cm := NewAESModuler()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(data, cm)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	data := []byte(testData)
	cm := NewAESModuler()
	blocks, _ := Encrypt(data, cm)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(blocks, cm)
	}
}

func Test_xor(t *testing.T) {
	type tcase struct {
		dstSize int
		srcSize int
	}
	cases := []tcase{}
	for i := wordSize - 1; i <= wordSize+1; i++ {
		cases = append(cases, tcase{
			srcSize: i,
			dstSize: i - 1,
		}, tcase{
			srcSize: i,
			dstSize: i,
		}, tcase{
			srcSize: i,
			dstSize: i + 1,
		})
	}
	for i, tc := range cases {
		dst := bytes.Repeat([]byte{0x01}, tc.dstSize)
		src := bytes.Repeat([]byte{0x10}, tc.srcSize)
		expected := bytes.Repeat([]byte{0x11}, tc.dstSize)
		for i := 0; i < tc.dstSize-tc.srcSize; i++ {
			expected[i] = 0x01
		}
		// t.Logf("expected %v for case %d", expected, i)

		xor(dst, src)
		if err := compareBytes(dst, expected); nil != err {
			t.Fatalf("case %d fail: %v", i, err)
		}
	}
}

func Test_xorWithInt(t *testing.T) {
	a := []byte{0x01, 0x02}
	b := 0x1020
	expected := []byte{0x11, 0x22}
	xorWithInt(a, a, b)

	if err := compareBytes(a, expected); nil != err {
		t.Fatal(err)
	}
}

func Test_bytesPP(t *testing.T) {
	b := make([]byte, 2)
	dst := make([]byte, 2)
	i := 0
	for ; i <= 0xffff; i++ {
		intToBytes(dst, i)
		if err := compareBytes(b, dst); nil != err {
			t.Fatal(err)
		}
		bytesPP(b)
	}

	t.Log("bytes:", b)
}

func Benchmark_intToBytes(b *testing.B) {
	dst := make([]byte, 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for i := 0; i <= 0xffff; i++ {
			intToBytes(dst, i)
		}
	}
}

func Benchmark_bytesPP(b *testing.B) {
	dst := make([]byte, 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for i := 0; i <= 0xffff; i++ {
			bytesPP(dst)
		}
	}
}

func Benchmark_xorWithInt(b *testing.B) {
	dst := make([]byte, 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for i := 0; i <= 0xffffff; i++ {
			xorWithInt(dst, dst, i)
		}
	}
}

func Benchmark_xorWithBytesI(b *testing.B) {
	dst := make([]byte, 2)
	bytesI := make([]byte, 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for i := 0; i <= 0xffffff; i++ {
			xor(dst, bytesI)
		}
	}
}

func Benchmark_genRandKey(b *testing.B) {
	key := make([]byte, 16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		genRandKey(key)
	}
}

func Benchmark_xor(b *testing.B) {
	dst := []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	src := []byte{0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		xor(dst, src)
	}
}

func compareBytes(got, expected []byte) error {
	if bytes.Compare(got, expected) != 0 {
		return fmt.Errorf("Compare two slice fail, got: %v, expected: %v", got, expected)
	}

	return nil
}
