// +build !windows

// Package libcrypto implements okapi interfaces using OpenSSL's libcrypto library.
package libcrypto

// #cgo LDFLAGS:  -L/usr/local/opt/openssl/lib -lcrypto
// #cgo CFLAGS: -I/usr/local/opt/openssl/include
// #include <openssl/err.h>
import "C"
import (
	"fmt"
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
	panic(fmt.Sprintf("libcrypto error %x:%s:%s", uint64(code), function, reason))
}
