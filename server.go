package pangcrypt

import (
	"bytes"
	"encoding/binary"

	lzo "github.com/rasky/go-lzo"
)

// ServerDecrypt decrypts Pangya server packets
func ServerDecrypt(data []byte, key byte) ([]byte, error) {
	if key >= 0x10 {
		return nil, KeyOutOfRangeError{key}
	}

	if len(data) < 8 {
		return nil, BufferTooSmallError{len(data), 8}
	}

	index := int(key)<<8 + int(data[0])
	buffer := append(data[:0:0], data...)

	buffer[7] ^= cryptTable[1][index]

	for i := 10; i < len(data); i++ {
		buffer[i] ^= buffer[i-4]
	}

	decompressed, err := lzo.Decompress1X(bytes.NewReader(buffer[8:]), 0, 0)
	if err != nil {
		return nil, err
	}
	return decompressed, nil
}

// ServerEncrypt encrypts Pangya server packets
func ServerEncrypt(data []byte, key byte, salt byte) ([]byte, error) {
	if key >= 0x10 {
		return nil, KeyOutOfRangeError{key}
	}

	index := int(key)<<8 + int(salt)

	compressed := lzo.Compress1X(data)
	buffer := make([]byte, len(compressed)+8)
	copy(buffer[8:], compressed)

	buffer[0] = salt
	buffer[3] = cryptTable[0][index] ^ cryptTable[1][index]
	binary.LittleEndian.PutUint16(buffer[1:3], uint16(len(buffer)-3))

	// TODO: ensure this is actually accurate.
	u := len(data)
	x := (u + u/255) & 0xff
	v := ((u - x) / 255)
	y := (v + v/255) & 0xff
	w := ((v - y) / 255)
	z := (w + w/255) & 0xff

	buffer[7] = byte(x)
	buffer[6] = byte(y)
	buffer[5] = byte(z)

	for i := len(buffer) - 1; i >= 10; i-- {
		buffer[i] ^= buffer[i-4]
	}

	buffer[7] ^= cryptTable[1][index]

	return buffer, nil
}
