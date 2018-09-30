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
		blocks, _ := Encrypt([]byte(testData), cm)

		got, _ := Decrypt(blocks, cm)
		if testData != string(got) {
			t.Fatal("Fail to match, decrypted:", got)
		}
		t.Log("Matched")
	}
}

func Test_xor(t *testing.T) {
	a := []byte{0x01, 0x02}
	b := []byte{0x10, 0x20}
	expected := []byte{0x11, 0x22}
	xor(a, b)

	if err := compareBytes(a, expected); nil != err {
		t.Fatal(err)
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

func compareBytes(got, expected []byte) error {
	if bytes.Compare(got, expected) != 0 {
		return fmt.Errorf("Test xor of two slice fail, got: %v, expected: %v", got, expected)
	}

	return nil
}
