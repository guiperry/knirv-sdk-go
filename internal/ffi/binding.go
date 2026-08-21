// Package ffi is the private CGO boundary for the KNIRV Rust core.
package ffi

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib -lknirv_sdk_core_linux_amd64 -lpthread -ldl -lm
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib -lknirv_sdk_core_linux_arm64 -lpthread -ldl -lm
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/lib -lknirv_sdk_core_darwin_arm64 -framework Security -framework CoreFoundation -lpthread -ldl -lm
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/lib -lknirv_sdk_core_darwin_amd64 -framework Security -framework CoreFoundation -lpthread -ldl -lm
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/lib -lknirv_sdk_core_windows_amd64 -lws2_32 -luserenv -lbcrypt
#include "knirv.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// InvokeProto calls the Rust core and copies its response into Go memory before
// releasing the Rust allocation. No C pointers cross this package boundary.
func InvokeProto(request []byte) ([]byte, error) {
	var input *C.uint8_t
	if len(request) != 0 {
		input = (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(request)))
	}

	var output C.knirv_bytes_t
	status := C.knirv_sdk_invoke_proto(C.knirv_bytes_t{ptr: input, len: C.size_t(len(request))}, &output)
	if status != C.KNIRV_STATUS_OK {
		return nil, fmt.Errorf("KNIRV native core returned status %d", int(status))
	}
	if output.ptr == nil || output.len == 0 {
		return nil, fmt.Errorf("KNIRV native core returned an empty response")
	}
	defer C.knirv_sdk_free_buffer(output)

	maxInt := int(^uint(0) >> 1)
	if uint64(output.len) > uint64(maxInt) {
		return nil, fmt.Errorf("KNIRV native response exceeds Go slice limits")
	}
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(output.ptr)), int(output.len))...), nil
}
