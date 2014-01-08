// +build !windows

package libcrypto

// #include <openssl/evp.h>
import "C"
import (
	"errors"
	"github.com/mkobetic/okapi"
	"unsafe"
)

func init() {
	okapi.MD4 = MD4.constructor()
	okapi.MD5 = MD5.constructor()
	okapi.SHA1 = SHA1.constructor()
	okapi.SHA224 = SHA224.constructor()
	okapi.SHA256 = SHA256.constructor()
	okapi.SHA384 = SHA384.constructor()
	okapi.SHA512 = SHA512.constructor()
	okapi.RIPEMD160 = RIPEMD160.constructor()
}

type Hash struct {
	digest []byte
	ctx    *C.EVP_MD_CTX
	md     *C.EVP_MD // libcrypto constant
}

type hashParams struct {
	md *C.EVP_MD
}

func (p hashParams) constructor() okapi.HashConstructor {
	return func() okapi.Hash {
		return NewHash(p)
	}
}

var (
	MD4       = hashParams{C.EVP_md4()}
	MD5       = hashParams{C.EVP_md5()}
	SHA1      = hashParams{C.EVP_sha1()}
	SHA224    = hashParams{C.EVP_sha224()}
	SHA256    = hashParams{C.EVP_sha256()}
	SHA384    = hashParams{C.EVP_sha384()}
	SHA512    = hashParams{C.EVP_sha512()}
	RIPEMD160 = hashParams{C.EVP_ripemd160()}
)

func NewHash(params hashParams) *Hash {
	algorithm := params.md
	h := &Hash{md: algorithm}
	h.ctx = new(C.EVP_MD_CTX)
	C.EVP_MD_CTX_init(h.ctx)
	check1(C.EVP_DigestInit_ex(h.ctx, algorithm, nil))
	return h
}

func (h *Hash) Size() int {
	return int(C.EVP_MD_size(h.md))
}

func (h *Hash) BlockSize() int {
	return int(C.EVP_MD_block_size(h.md))
}

func (h *Hash) Reset() {
	check1(C.EVP_DigestInit_ex(h.ctx, nil, nil))
}

func (h *Hash) Clone() okapi.Hash {
	ctx2 := new(C.EVP_MD_CTX)
	C.EVP_MD_CTX_init(ctx2)
	C.EVP_MD_CTX_copy_ex(ctx2, h.ctx)
	return &Hash{md: h.md, ctx: ctx2}
}

func (h *Hash) Digest() []byte {
	if h.digest != nil {
		return h.digest
	}
	h.digest = make([]byte, h.Size())
	check1(C.EVP_DigestFinal_ex(h.ctx, (*C.uchar)(&h.digest[0]), nil))
	return h.digest
}

func (h *Hash) Write(data []byte) (int, error) {
	if h.digest != nil {
		return 0, errors.New("Cannot write into finalized hash")
	}
	check1(C.EVP_DigestUpdate(h.ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))))
	return len(data), nil
}

func (h *Hash) Close() {
	if h.ctx == nil {
		return
	}
	defer func() {
		h.ctx = nil
	}()
	C.EVP_MD_CTX_cleanup(h.ctx)
}
