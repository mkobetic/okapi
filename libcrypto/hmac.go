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
	// okapi.HMAC = NewHMAC
}

type HMAC struct {
	digest []byte
	ctx    *C.HMAC_CTX
	md     *C.EVP_MD // libcrypto constant
}

func NewHMAC(params hashParams, key []byte) *HMAC {
	algorithm := params.md
	h := &HMAC{md: algorithm}
	h.ctx = new(C.HMAC_CTX)
	C.HMAC_CTX_init(h.ctx)
	check1(C.HMAC_Init_ex(h.ctx, unsafe.Pointer(&key[0]), C.int(len(key)), algorithm, nil))
	return h
}

func (h *HMAC) Size() int {
	return int(C.EVP_MD_size(h.md))
}

func (h *HMAC) BlockSize() int {
	return int(C.EVP_MD_block_size(h.md))
}

func (h *HMAC) Reset() {
	check1(C.HMAC_Init_ex(h.ctx, nil, 0, nil, nil))
}

func (h *HMAC) Clone() okapi.Hash {
	panic("libcrypto does not support HMAC cloning!")
}

func (h *HMAC) Digest() []byte {
	if h.digest != nil {
		return h.digest
	}
	h.digest = make([]byte, h.Size())
	check1(C.HMAC_Final(h.ctx, (*C.uchar)(&h.digest[0]), nil))
	return h.digest
}

func (h *HMAC) Write(data []byte) (int, error) {
	if h.digest != nil {
		return 0, errors.New("Cannot write into finalized hash")
	}
	check1(C.HMAC_Update(h.ctx, (*C.uchar)(&data[0]), C.size_t(len(data))))
	return len(data), nil
}

func (h *HMAC) Close() {
	if h.ctx == nil {
		return
	}
	defer func() {
		h.ctx = nil
	}()
	C.HMAC_CTX_cleanup(h.ctx)
}
