package pangcrypt

import "encoding/binary"

// ClientDecrypt decrypts PangYa client packets.
func ClientDecrypt(data []byte, key byte) ([]byte, error) {
	if key >= 0x10 {
		return nil, KeyOutOfRangeError{key}
	}

	if len(data) < 5 {
		return nil, BufferTooSmallError{len(data), 5}
	}

	index := int(key)<<8 + int(data[0])
	buffer := append(data[:0:0], data...)

	buffer[4] = cryptTable[1][index]
	for i := 8; i < len(data); i++ {
		buffer[i] ^= buffer[i-4]
	}

	return buffer[5:], nil
}

// ClientEncrypt encrypts PangYa client packets.
func ClientEncrypt(data []byte, key byte, salt byte) ([]byte, error) {
	if key >= 0x10 {
		return nil, KeyOutOfRangeError{key}
	}

	buffer := make([]byte, len(data)+5)
	copy(buffer[5:], data)

	index := int(key)<<8 + int(salt)

	buffer[0] = salt
	buffer[3] = 0
	buffer[4] = cryptTable[1][index]
	binary.LittleEndian.PutUint16(buffer[1:3], uint16(len(buffer)-4))

	for i := len(buffer) - 1; i >= 8; i-- {
		buffer[i] ^= buffer[i-4]
	}

	buffer[4] ^= cryptTable[0][index]

	return buffer, nil
}
