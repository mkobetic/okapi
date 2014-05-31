package tests

import (
	"fmt"
	. "github.com/mkobetic/okapi"
	_ "github.com/mkobetic/okapi/libcrypto"
	_ "testing"
)

func ExampleRandom() {
	random := DefaultRandom.New()
	defer random.Close()
	out := make([]byte, 10)
	size, err := random.Read(out)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Generated %d random bytes\n", size)
	// Output:
	// Generated 10 random bytes
}
