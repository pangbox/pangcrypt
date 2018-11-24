# PangCrypt [![Build Status](https://travis-ci.org/pangbox/pangcrypt.svg)](https://travis-ci.org/pangbox/pangcrypt) [![codecov.io](https://codecov.io/github/pangbox/pangcrypt/coverage.svg?branch=master)](https://codecov.io/github/pangbox/pangcrypt?branch=master) [![godoc.org](https://img.shields.io/badge/godoc-reference-5272B4.svg?style=flat-square)](https://godoc.org/github.com/pangbox/pangcrypt) [![Go Report Card](https://goreportcard.com/badge/github.com/pangbox/pangcrypt)](https://goreportcard.com/report/github.com/pangbox/pangcrypt)

PangCrypt is an implementation of the PangYa transport cryptography. These routines are used by the PangYa Client and Server to obfuscate communication.

## Pang.dll
There is an implementation of HSReina's Pang.dll interface using PangCrypt in the `dll/pang` package.

## Unpangle
There's an included tool for decrypting PangYa packets directly in the `cmd/unpangle` package.

## Other Implementations

PangCrypt is largely based on analysis of the messages using Wireshark. The tables of data used in the crypto routines were dumped from memory.

There is some prior art available. These were not used to implement PangCrypt in any way, but may serve as useful references.

  * [davedevils/Pang-dll](https://github.com/davedevils/Pang-dll): This seems to be the most complete library available, appearing to contain all of the necessary operations. However, it did not seem to produce correct results in my cursory testing. I did not debug the incorrect results. It is possible this library works if used correctly.
  * [Lucas-Firefox/Pang.dll-Encrypt-Decrypt-by-Firefox](https://github.com/Lucas-Firefox/Pang.dll-Encrypt-Decrypt-by-Firefox): This code appears to be missing important parts of the crypto routines, including the headers and LZO compression. For this reason, I did not test it.
  * [Lucas-Firefox/Source:packets tool/crypts.pas](https://github.com/Lucas-Firefox/Source/blob/master/packets%20tool/crypts.pas): This code looks like it was extracted out of a binary containing a C implementation of the crypto routines, then embedded in a Pascal program using asm blocks. I did not read or evaluate the actual routines, though the names of the routines and other hints suggest this is a complete implementation of the algorithm. I did not test it.

### Terminology

Other PangYa encryption routines available seem to differ in what they call 'client encrypt' and so forth. For example, HSReina's pang.dll interface _seems_ to use 'client' to refer to the routines that would be used by the client, so the 'client decrypt' would actually decrypt server packets, and the 'client encrypt' would encrypt client packets.

The terminology used in PangCrypt is as follows:

  * Client Encrypt - Encrypts packets from client, sent to server.
  * Client Decrypt - Decrypts packets from client, sent to server.
  * Server Encrypt - Encrypts packets from server, sent to client.
  * Server Decrypt - Decrypts packets from server, sent to client.

# PangYa Transport Encryption

## Hello packet

Firstly, there is a 'hello' message sent from the server to the client. This message is important for the encryption.

```
0000   00 0b 00 00 00 00 0c 00 00 00 75 27 00 00         ..........u'..
```

The most important one is index 6, `0x0c`. This is the key. It will be used throughout the entire TCP session. The hello message varies per server (and per region,) but one of the bytes will be the key in every message. In PangYa US GameServer, it is the last byte, for example.

## Anatomy of a client-side packet

Here's an encrypted login client, sent from PangYa:

```
0000   48 3c 00 00 a2 01 00 04 68 6b 6f 6c 6e 4a 6f 58   H<..¢...hkolnJoX
0010   57 18 46 06 7b 7b 02 02 74 71 75 70 05 05 02 07   W.F.{{..tqup....
0020   72 73 76 77 04 7c 76 06 73 0a 04 70 02 74 01 42   rsvw.|v.s..p.t.B
0030   34 46 36 00 00 00 00 00 00 00 00 00 00 00 00 00   4F6.............
```

...Here's the actual, decrypted message:

```
0000   01 00 04 00 6a 6f 68 6e 20 00 30 39 38 46 36 42   ....john .098F6B
0010   43 44 34 36 32 31 44 33 37 33 43 41 44 45 34 45   CD4621D373CADE4E
0020   38 33 32 36 32 37 42 34 46 36 00 00 00 00 00 00   832627B4F6......
0030   00 00 00 00 00 00 00 00 00 00 00                  ...........
```

The encrypted packet adds 5 bytes to the front of the packet. Some bytes of plain text are visible in the cipher text, including the last 4 digits of the MD5 sum. This is apparent when you consider the algorithm:

  * The first byte of the encrypted version is just a random value. I call it the 'salt'.
  * Next, the second two bytes are the length, encoded as an unsigned 16-bit little endian value. It excludes the first 4 bytes. This way, when reading PangYa packets, you can simply read four bytes, then use this value as the exact amount of bytes you need to read more.
  * The fourth byte seems to just be zero.
  * The fifth byte is where the key comes into play. There are two tables, each 0x1000 bytes long. You pick this byte out of the first table, by grabbing the index `key << 8 + salt`. Later, it is XOR'd by the same index of the second table.
  * Each byte from the end to index 8 is XOR'd with the byte 4 positions behind it.

## Anatomy of a server-side packet

Here's an encrypted authorization packet, sent from a PangYa server:

```
0000   29 14 00 06 00 00 00 be 1c 10 00 0c 1c 25 30 33   )......¾.....%03
0010   41 76 09 70 50 43 39                              Av.pPC9
```

Here is the underlying, decrypted message.

```
0000   10 00 07 00 35 30 34 41  43 39 44                 ....504AC9D
```

Server-side packets are compressed with LZO1X-1 before they are encrypted, complicating things a bit.

LZO1X-1 is an older compression routine based on LZ. It has opcodes whose interpretations change based on state. LZO was popular around the time PangYa was created, and famously was used by the Linux kernel to great effect. Interesting, LZO is a GPLv2 library, suggesting Ntreev may have violated the license terms for LZO by not distributing the PangYa source code.

Documentation on LZO is scant. It contains many different algorithms, none of which I've been able to find any useful documentation on, except for [this document](http://www.infradead.org/~mchehab/kernel_docs/unsorted/lzo.html) describing LZO as it exists in the Linux kernel.

In all of the packets I've seen, server-side packets are always compressed, and client-side packets are never compressed.

Server-side packets have an 8-byte long header.

  * The first byte is the salt, like in the client-side encryption.
  * The next two bytes are the length encoded as an unsigned 16-bit little endian integer, just like before. This time, it's the full length of the packet minus 3, instead of minus 4. I don't really know why.
  * The next byte is both of the crypt tables, at index `key << 8 + salt`, XOR'd together.
  * The next four bytes are tricky. It appears to be a sort of checksum based on the length of the original data. If you encode this data wrong, the PangYa client will crash - though it is unclear if that is defensive or if it actually uses this value to allocate a buffer.
  * Each byte from the end to index 10 are XOR'd with the byte 4 positions behind it.
  * The byte at index 7 is XOR'd with the second crypt table at index `key << 8 + salt`.