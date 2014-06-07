package gocrypto

import (
	"testing"
)

func TestRandom(t *testing.T) {
	random := DefaultRandom.New()
	defer random.Close()
	out := make([]byte, 10)
	size, err := random.Read(out)
	if err != nil {
		t.Fatal(err)
	}
	if size != 10 {
		t.Fatalf("Wrong result size %d, expected 10", size)
	}
}
