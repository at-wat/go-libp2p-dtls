package tlsdiag

import (
	"context"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/libp2p/go-libp2p-core/peer"
	libp2pdtls "go-libp2p-dtls"
)

func StartClient() error {
	port := flag.Int("p", 5533, "port")
	peerIDString := flag.String("id", "", "peer ID")
	keyType := flag.String("key", "ecdsa", "rsa, ecdsa, ed25519 or secp256k1")
	flag.Parse()

	priv, err := generateKey(*keyType)
	if err != nil {
		return err
	}

	peerID, err := peer.IDB58Decode(*peerIDString)
	if err != nil {
		return err
	}

	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return err
	}
	fmt.Printf(" Peer ID: %s\n", id.Pretty())
	tp, err := libp2pdtls.New(priv)
	if err != nil {
		return err
	}

	localAddr :=  net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	remoteAddr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: *port}

	fmt.Printf("Dialing %s\n", remoteAddr)
	conn, err := net.DialUDP("udp", &localAddr, &remoteAddr)
	if err != nil {
		return err
	}
	fmt.Printf("Dialed raw connection to %s\n", conn.RemoteAddr())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sconn, err := tp.SecureOutbound(ctx, conn, peerID)
	if err != nil {
		return err
	}
	fmt.Printf("Authenticated server: %s\n", sconn.RemotePeer().Pretty())
	data := make([]byte, 8192)
	_, err = sconn.Read(data)
	if err != nil {
		return err
	}
	fmt.Printf("Received message from server: %s\n", string(data))
	return nil
}
