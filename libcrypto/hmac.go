// +build !windows

package libcrypto

// #include <openssl/hmac.h>
import "C"
import (
	"errors"
	"github.com/mkobetic/okapi"
	"unsafe"
)

func init() {
	okapi.HMAC = HMAC
}

type MACSpec struct{}

var (
	HMAC = MACSpec{}
)

func (ms MACSpec) New(hs okapi.HashSpec, key []byte) okapi.Hash {
	algorithm := hs.(HashSpec).md
	h := &hmac{md: algorithm}
	h.ctx = new(C.HMAC_CTX)
	C.HMAC_CTX_init(h.ctx)
	check1(C.HMAC_Init_ex(h.ctx, unsafe.Pointer(&key[0]), C.int(len(key)), algorithm, nil))
	return h
}

// Implements HMAC algorithm, but is private so that it doesn't conflict with the variable above
type hmac struct {
	digest []byte
	ctx    *C.HMAC_CTX
	md     *C.EVP_MD // libcrypto constant
}

func (h *hmac) Size() int {
	return int(C.EVP_MD_size(h.md))
}

func (h *hmac) BlockSize() int {
	return int(C.EVP_MD_block_size(h.md))
}

func (h *hmac) Reset() {
	check1(C.HMAC_Init_ex(h.ctx, nil, 0, nil, nil))
}

func (h *hmac) Clone() okapi.Hash {
	panic("libcrypto does not support HMAC cloning!")
}

func (h *hmac) Digest() []byte {
	if h.digest != nil {
		return h.digest
	}
	h.digest = make([]byte, h.Size())
	check1(C.HMAC_Final(h.ctx, (*C.uchar)(&h.digest[0]), nil))
	return h.digest
}

func (h *hmac) Write(data []byte) (int, error) {
	if h.digest != nil {
		return 0, errors.New("Cannot write into finalized hash")
	}
	check1(C.HMAC_Update(h.ctx, (*C.uchar)(&data[0]), C.size_t(len(data))))
	return len(data), nil
}

func (h *hmac) Close() {
	if h.ctx == nil {
		return
	}
	defer func() {
		h.ctx = nil
	}()
	C.HMAC_CTX_cleanup(h.ctx)
}
