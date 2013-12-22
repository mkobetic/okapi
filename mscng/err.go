// +build windows

package mscng

// #cgo LDFLAGS:  -lbcrypt
// #include <windows.h>
import "C"
import (
	"fmt"
)

func check(err C.NTSTATUS) {
	if int(err) == 0 {
		return
	}
	panic(fmt.Sprintf("CNG error %x", uint64(err)))
}
