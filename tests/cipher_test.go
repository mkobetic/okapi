package tests

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/mkobetic/okapi"
	_ "github.com/mkobetic/okapi/libcrypto"
	_ "testing"
)

func ExampleCipherWriter() {
	encrypted := new(bytes.Buffer)
	key := []byte("0123456789ABCDEF")
	iv := []byte("0123456789ABCDEF")
	aes := okapi.NewCipherWriter(encrypted, okapi.AES_CTR, key, iv, nil)
	plain := []byte("Message in a bottle!")
	count, err := aes.Write(plain)
	fmt.Printf("Input size %d, count %d, error %v\n", len(plain), count, err)
	aes.Close()
	fmt.Print(hex.EncodeToString(encrypted.Bytes()))
	// Output:
	// Input size 20, count 20, error <nil>
	// c0e62e7f9ebfdff5ec90ab23b4a64efc59a25deb
}
