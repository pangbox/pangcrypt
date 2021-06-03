package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/davecgh/go-spew/spew"
	"github.com/pangbox/pangcrypt"
)

var (
	key     = 0
	server  = false
	useSpew = true
)

func init() {
	flag.IntVar(&key, "key", key, "encryption key (from 0 to 15)")
	flag.BoolVar(&server, "server", server, "use server-side decryption")
	flag.BoolVar(&useSpew, "use_spew", useSpew, "print in spew format")
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
}

func main() {
	var err error

	packet := flag.Arg(0)
	data := []byte{}

	octet := make([]rune, 0, 2)

	// Parse octet string.
	for _, nibble := range packet {
		isHex := (nibble >= '0' && nibble <= '9') || (nibble >= 'a' && nibble <= 'f') || (nibble >= 'A' && nibble <= 'F')
		if !isHex {
			continue
		}

		octet = append(octet, nibble)

		if len(octet) == 2 {
			bits, err := strconv.ParseUint(string(octet), 16, 8)
			if err != nil {
				log.Fatalln("invalid octet:", err)
			}
			data = append(data, byte(bits))
			octet = octet[0:0]
		}
	}

	// Select crypt function and configuration.
	crypt := pangcrypt.ClientDecrypt
	lenoff := 4
	minlen := 5

	if server {
		crypt = pangcrypt.ServerDecrypt
		lenoff = 3
		minlen = 8
	}

	// Select dump routine.
	dump := func(d []byte) { fmt.Printf("%#v\n", d) }
	if useSpew {
		dump = func(d []byte) { spew.Dump(d) }
	}

	// Loop until we don't have enough data left to decode another packet.
	for len(data) > minlen {
		var msg []byte

		// Read one message off of the buffer.
		mlen := int(binary.LittleEndian.Uint16(data[1:3])) + lenoff
		if mlen > len(data) {
			log.Fatalf("error: message is longer than buffer (message length: %d, buffer length: %d)\n", mlen, len(data))
		}
		msg, data = data[:mlen], data[mlen:]

		// Decrypt the message.
		msg, err = crypt(msg, byte(key))
		if err != nil {
			log.Println("warning: skipping invalid message")
			continue
		}

		// Dump the message.
		dump(msg)
	}

	if len(data) > 0 {
		log.Printf("warning: %d trailing byte(s): %+v\n", len(data), data)
	}
}
