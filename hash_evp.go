package okapi

// #cgo LDFLAGS:  -L/usr/local/opt/openssl/lib -lcrypto
// #cgo CFLAGS: -I/usr/local/opt/openssl/include
// #include <openssl/evp.h>
// #include <openssl/err.h>
import "C"
import (
	"fmt"
	"unsafe"
)

type Hash struct {
	Digest   []byte
	evp_ctx  *C.EVP_MD_CTX
	evp_ctx2 *C.EVP_MD_CTX
	evp_md   *C.EVP_MD // openssl constant
}

var (
	MD5    = C.EVP_md5()
	SHA1   = C.EVP_sha1()
	SHA256 = C.EVP_sha256()
	SHA512 = C.EVP_sha512()
	RMD160 = C.EVP_ripemd160()
)

func init() {
	C.ERR_load_crypto_strings()
}

func check(err C.int) {
	if int(err) == 1 {
		return
	}
	code := C.ERR_get_error()
	function := C.GoString(C.ERR_func_error_string(code))
	reason := C.GoString(C.ERR_reason_error_string(code))
	panic(fmt.Sprintf("err %x:%s:%s", uint64(code), function, reason))
}

func NewHash(algorithm *C.EVP_MD) *Hash {
	h := &Hash{evp_md: algorithm}
	h.Digest = make([]byte, h.Size())
	h.evp_ctx = new(C.EVP_MD_CTX)
	C.EVP_MD_CTX_init(h.evp_ctx)
	h.evp_ctx2 = new(C.EVP_MD_CTX)
	C.EVP_MD_CTX_init(h.evp_ctx2)
	check(C.EVP_DigestInit_ex(h.evp_ctx, algorithm, nil))
	return h
}

func (h *Hash) Size() int {
	return int(C.EVP_MD_size(h.evp_md))
}

func (h *Hash) BlockSize() int {
	return int(C.EVP_MD_block_size(h.evp_md))
}

func (h *Hash) Reset() {
	check(C.EVP_DigestInit_ex(h.evp_ctx, nil, nil))
}

func (h *Hash) Sum(b []byte) []byte {
	C.EVP_MD_CTX_copy_ex(h.evp_ctx2, h.evp_ctx)
	check(C.EVP_DigestFinal_ex(h.evp_ctx2, (*C.uchar)(&h.Digest[0]), nil))
	return append(b, h.Digest...)
}

func (h *Hash) Write(data []byte) (int, error) {
	check(C.EVP_DigestUpdate(h.evp_ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))))
	return len(data), nil
}

func (h *Hash) Close() {
	if h.evp_ctx == nil {
		return
	}
	defer func() {
		h.evp_ctx = nil
		h.evp_ctx2 = nil
	}()
	C.EVP_MD_CTX_cleanup(h.evp_ctx)
	C.EVP_MD_CTX_cleanup(h.evp_ctx2)
}
