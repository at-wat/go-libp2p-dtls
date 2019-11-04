# go-libp2p-dtls

**Status: Alpha / Proof of Concept**

This repo contains an initial proof-of-concept integration of
[go-libp2p](https://github.com/libp2p/go-libp2p) with the
[pion/dtls](https://github.com/pion/dtls) implementation of the [Datagram
Transport Security
Layer](https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security) security
protocol.

This is part of an [ongoing effort](https://github.com/libp2p/specs/issues/225)
to provide a message-oriented transport interface for libp2p that can run over
unreliable UDP-based transports.

## Context

One of the key features for a packet-oriented libp2p that we know we'll need is
an efficient security channel that can operate over an unreliable transport.

In the medium / long term, we'll be investing time in designing and implementing
a security protocol based on the [Noise Protocol
Framework](https://noiseprotocol.org). This will involve adapting our
exisitng [noise-libp2p spec](https://github.com/libp2p/specs/tree/master/noise)
to work with unreliable transports.

While that's happening, it _may_ be helpful to use DTLS as a security protocol,
so that we can work on the other pieces of the message-orientation story without
having to "stub out" the security protocol and work completely in plaintext.

Since DTLS is an established protocol with implementations in many of libp2p's
host languages, it seemed worth spending a little time on to see if we can make
it work.

## Details

This repo is largely based on
[go-libp2p-tls](https://github.com/libp2p/go-libp2p-tls), which provides a
libp2p
[SecureTransport](https://godoc.org/github.com/libp2p/go-libp2p-core/sec#SecureTransport)
implementation based on TLS 1.3.

This works by using a self-signed certificate for the TLS connection and
embedding the libp2p peer's public key in an x509 certificate extension. See the
[libp2p TLS spec](https://github.com/libp2p/specs/blob/master/tls/tls.md) for
details.

The same approach works with DTLS, since DTLS also uses x509 certificates that
support extensions.

Most of the relevant code lives in [crypto.go](./crypto.go), which is based on
the the crypto.go from go-libp2p-tls.

## Try it out

You can us the `tlsdiag` helper command to run a simple server and client.

Run the server:

``` shell
go run cmd/tlsdiag.go server
 fsGenerated new peer with an ECDSA key. Peer ID: QmNqcy4tn62doEvRqyEPrnp4yaPHTJUhmVot3C6J4Ade2f
Listening for new connections on 127.0.0.1:5533
Now run the following command in a separate terminal:
        go run cmd/tlsdiag.go client -p 5533 -id QmNqcy4tn62doEvRqyEPrnp4yaPHTJUhmVot3C6J4Ade2f
```

Run the client (pasting in output from above):

``` shell
go run cmd/tlsdiag.go client -p 5533 -id QmNqcy4tn62doEvRqyEPrnp4yaPHTJUhmVot3C6J4Ade2f

Generated new peer with an ECDSA key. Peer ID: QmQpj8Meq7v5seamHxqJF8vHgxJSfuLbgFi8X5mYYg9Hum
Dialing {127.0.0.1 %!s(int=5533) }
Dialed raw connection to 127.0.0.1:5533
Authenticated server: QmNqcy4tn62doEvRqyEPrnp4yaPHTJUhmVot3C6J4Ade2f
Received message from server: Hello client!
```

##  Observations

The pion dtls library API exposes `net.Conn` as the connection type for both
dialing and listening. Under the hood, the listener wraps go's `PacketConn`
type, which is used for listening on UDP ports, and it maintains a map of remote
addresses to an internal `Conn` implementation. As packets come in, their source
address is looked up in the map and data is routed to the correct `Conn` instance.

I had to copy that code over (see
[internal/udp/conn.go](./internal/udp/conn.go)), because the pion
implementation's public `Listener` type calls `dtls.Server` when a new incoming
connection is established. We need to call that method ourselves, because we
customize the dtls config for each incoming connection, so that we can extract
the remote party's public key from the certificate extension.

Anyway, using `net.Conn` is kind of nice, because it means that libp2p's
existing `SecureTransport` interface can be used "out of the box", since it also
uses `net.Conn` to secure both incoming and outgoing connections.

That said, it's too early in the packet-orientation design to know if this is an
appropriate API for libp2p. We may want to clearly distinguish between streaming
`SecureTransport`s and packet-based secure transports. And we may also want more
direct control of the underlying `PacketConn` at a layer "below" the security
protocol.
