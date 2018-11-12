# Unpangle
Unpangle is a simple helper command that lets you unmangle PangYa packets directly.

It is designed to consume the copy-paste format from Wireshark, which is simply a string of hex-formatted octets delimited by colons, like this: `54:3a:00:00:56:01:00:02:...`

To use, first determine the crypto key for the session you are looking at by looking at the hello packet. Then, copy a data segment of a server or client packet, and run unpangle with it:

```
$ unpangle -key 2 54:3a:00:00:56:01:00:02:ab:62:65:22:00:53:5c:18:46:06:7b:7b:02:02:74:71:75:70:05:05:02:07:72:73:76:77:04:7c:76:06:73:0a:04:70:02:74:01:42:34:46:36:00:00:00:00:00:00:00:00:00:00:00:00:00
```

```
([]uint8) (len=57 cap=59) {
 00000000  01 00 02 00 63 65 20 00  30 39 38 46 36 42 43 44  |....ce .098F6BCD|
 00000010  34 36 32 31 44 33 37 33  43 41 44 45 34 45 38 33  |4621D373CADE4E83|
 00000020  32 36 32 37 42 34 46 36  00 00 00 00 00 00 00 00  |2627B4F6........|
 00000030  00 00 00 00 00 00 00 00  00                       |.........|
}
```

## Installation
Unpangle is written in pure Go. You can install it like so:

```
$ go get -v github.com/pangbox/pangcrypt/cmd/unpangle

...

$ unpangle -help
```

> You must have the [Go toolchain](https://golang.org/dl/) and [Git](https://git-scm.com/downloads) installed. Also, in order to be able to run Unpangle after running `go get`, you will need to ensure that your `$PATH` (Unix-like) or `%PATH%` (Windows) environment variable contains `$PATH/go/bin` (Unix-like) or `C:\Users\[your username]\go\bin` (Windows.)
>
> * [Adding a folder to $PATH (Unix-like)](https://stackoverflow.com/a/7360945)
> * [Adding a folder to %PATH% (Windows)](https://stackoverflow.com/a/44272417)

## Caveats
Packets larger than the MTU will span multiple TCP packets and may be difficult to copy out of Wireshark. TCP sessions that span across the real Internet may also contain retransmissions and other anomalies. You need to use a TCP reconstruction algorithm to properly extract packets with this issue.

PangYa packets will sometimes contain multiple messages in them, so Unpangle treats data as a stream that starts on a packet boundary. If you provide multiple messages, Unpangle will print each message individually, warning you if there is any left over data that was not parsed.