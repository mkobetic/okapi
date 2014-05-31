// +build !windows

package libcrypto

// #include <openssl/rand.h>
import "C"
import (
	"github.com/mkobetic/okapi"
)

func init() {
	okapi.DefaultRandom = DefaultRandom
}

type RandomSpec struct{}

var (
	DefaultRandom = RandomSpec{}
)

func (rs RandomSpec) New() okapi.Random {
	return &Random{}
}

type Random struct {
}

func (r *Random) Read(b []byte) (int, error) {
	err := error1(C.RAND_bytes((*C.uchar)(&b[0]), C.int(len(b))))
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (r *Random) Close() {
}
