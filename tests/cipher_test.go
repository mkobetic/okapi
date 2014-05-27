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
	aes := okapi.AES_CTR.NewWriter(encrypted, key, iv, nil)
	plain := []byte("Message in a bottle!")
	count, err := aes.Write(plain)
	fmt.Printf("Input size %d, count %d, error %v\n", len(plain), count, err)
	aes.Close()
	fmt.Print(hex.EncodeToString(encrypted.Bytes()))
	// Output:
	// Input size 20, count 20, error <nil>
	// c0e62e7f9ebfdff5ec90ab23b4a64efc59a25deb
}

func ExampleCipherReader() {
	encrypted, _ := hex.DecodeString("c0e62e7f9ebfdff5ec90ab23b4a64efc59a25deb")
	decrypted := make([]byte, 50)
	key := []byte("0123456789ABCDEF")
	iv := []byte("0123456789ABCDEF")
	aes := okapi.AES_CTR.NewReader(bytes.NewReader(encrypted), key, iv, nil)
	count, err := aes.Read(decrypted)
	fmt.Printf("Output count %d, error %v\n", count, err)
	aes.Close()
	fmt.Print(string(decrypted[:count]))
	// Output:
	// Output count 20, error EOF
	// Message in a bottle!
}
