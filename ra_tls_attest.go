package main

// #cgo CFLAGS: -I/usr/include
// #cgo LDFLAGS: -L/lib/x86_64-linux-gnu -ldl -lra_tls_attest
// #include <ra_tls.h>
// #include <stdlib.h>
// #include <stddef.h>
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// Function to create a key pair and a corresponding RA-TLS certificate in DER format
func createKeyAndCrtDer() ([]byte, []byte, error) {
	var derKey *C.uchar
	var derKeySize C.size_t
	var derCrt *C.uchar
	var derCrtSize C.size_t

	// Load the shared library
	lib := C.dlopen(C.CString("libra_tls_attest.so"), C.RTLD_NOW)
	if lib == nil {
		panic(errors.New("failed to load libra_tls_attest.so"))
	}
	defer C.dlclose(lib)

	// Call the C function to create key and certificate
	ret := C.ra_tls_create_key_and_crt_der(&derKey, &derKeySize, &derCrt, &derCrtSize)
	if ret != 0 {
		return nil, nil, fmt.Errorf("failed to create key and certificate: %v", ret)
	}

	// Convert C arrays to Go byte slices
	keyBytes := C.GoBytes(unsafe.Pointer(derKey), C.int(derKeySize))
	crtBytes := C.GoBytes(unsafe.Pointer(derCrt), C.int(derCrtSize))

	// Free memory allocated by C function
	C.free(unsafe.Pointer(derKey))
	C.free(unsafe.Pointer(derCrt))

	return keyBytes, crtBytes, nil
}

func main() {
	// Call function to create key pair and certificate
	key, crt, err := createKeyAndCrtDer()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Print key and certificate
	fmt.Println("Key:", key)
	fmt.Println("Certificate:", crt)
}
