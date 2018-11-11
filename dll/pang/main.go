package main

// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
import "C"
import (
	"unsafe"

	"github.com/pangbox/pangcrypt"
)

func arrayToSlice(array *C.char, size int) []byte {
	slice := make([]byte, size)
	C.memcpy(unsafe.Pointer(&slice[0]), unsafe.Pointer(array), C.size_t(size))
	return slice
}

func sliceToArray(slice []byte) *C.char {
	array := (*C.char)(C.malloc(C.size_t(len(slice))))
	C.memcpy(unsafe.Pointer(array), unsafe.Pointer(&slice[0]), C.size_t(len(slice)))
	return array
}

//export pangya_client_decrypt
func pangya_client_decrypt(buffin *C.char, size int, buffout **C.char, buffoutSize *int, key byte) int {
	input := arrayToSlice(buffin, size)

	output, err := pangcrypt.ClientDecrypt(input, key)
	if err != nil {
		return 0
	}
	*buffout = sliceToArray(output)
	*buffoutSize = len(output)
	return 1
}

//export pangya_client_encrypt
func pangya_client_encrypt(buffin *C.char, size int, buffout **C.char, buffoutSize *int, key byte) int {
	input := arrayToSlice(buffin, size)

	output, err := pangcrypt.ServerEncrypt(input, key, 0)
	if err != nil {
		return 0
	}

	*buffout = sliceToArray(output)
	*buffoutSize = len(output)
	return 1
}

//export pangya_server_decrypt
func pangya_server_decrypt(buffin *C.char, size int, buffout **C.char, buffoutSize *int, key byte) int {
	input := arrayToSlice(buffin, size)

	output, err := pangcrypt.ServerDecrypt(input, key)
	if err != nil {
		return 0
	}

	*buffout = sliceToArray(output)
	*buffoutSize = len(output)
	return 1
}

//export pangya_server_encrypt
func pangya_server_encrypt(buffin *C.char, size int, buffout **C.char, buffoutSize *int, key byte) int {
	input := arrayToSlice(buffin, size)

	output, err := pangcrypt.ClientEncrypt(input, key, 0)
	if err != nil {
		return 0
	}

	*buffout = sliceToArray(output)
	*buffoutSize = len(output)
	return 1
}

//export pangya_free
func pangya_free(buffout **C.char) {
	C.free(unsafe.Pointer(*buffout))
}

//export pangya_deserialize
func pangya_deserialize(deserialize uint32) uint32 {
	return deserialize
}

func main() {}
