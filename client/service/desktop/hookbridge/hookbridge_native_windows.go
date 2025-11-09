//go:build windows && cgo

package hookbridge

/*
#cgo windows CFLAGS: -I${SRCDIR}/../../native/umh/include -I${SRCDIR}/../../native/umh/vendor/include
#cgo windows CXXFLAGS: -std=c++17 -DNOMINMAX -DUNICODE -D_UNICODE -I${SRCDIR}/../../native/umh/include -I${SRCDIR}/../../native/umh/vendor/include -I${SRCDIR}/../../native/umh/vendor/third_party/minhook/include
#cgo windows LDFLAGS: -luser32 -lgdi32
#include <stdlib.h>
#include "spark_umh.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func nativeInit(cfg Config) error {
	if C.spark_umh_init() != 0 {
		return fmt.Errorf("spark_umh_init failed")
	}
	return nil
}

func nativeApply(p Policy) error {
	cConn := C.CString(p.ConnectionID)
	defer C.free(unsafe.Pointer(cConn))
	forceInput := C.int(0)
	if p.ForceInput {
		forceInput = 1
	}
	forceCapture := C.int(0)
	if p.ForceCapture {
		forceCapture = 1
	}
	if C.spark_umh_apply(cConn, forceInput, forceCapture) != 0 {
		return fmt.Errorf("spark_umh_apply failed")
	}
	return nil
}

func nativeRelease(connectionID string) error {
	cConn := C.CString(connectionID)
	defer C.free(unsafe.Pointer(cConn))
	if C.spark_umh_release(cConn) != 0 {
		return fmt.Errorf("spark_umh_release failed")
	}
	return nil
}

func nativeShutdown() {
	C.spark_umh_shutdown()
}
