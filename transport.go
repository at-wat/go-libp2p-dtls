package go_libp2p_dtls

import (
	"context"
	"errors"
	ci "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
	"net"

	"github.com/pion/dtls"
)

// ID is the protocol ID (used when negotiating with multistream)
const ID = "/dtls/1.0.0"

// Transport constructs secure communication sessions for a peer.
type Transport struct {
	identity *Identity

	localPeer peer.ID
	privKey   ci.PrivKey
}

// New creates a TLS encrypted transport
func New(key ci.PrivKey) (*Transport, error) {
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return nil, err
	}
	t := &Transport{
		localPeer: id,
		privKey:   key,
	}

	identity, err := NewIdentity(key)
	if err != nil {
		return nil, err
	}
	t.identity = identity
	return t, nil
}

var _ sec.SecureTransport = &Transport{}

// SecureInbound runs the TLS handshake as a server.
func (t *Transport) SecureInbound(ctx context.Context, insecure net.Conn) (sec.SecureConn, error) {
	config, keyCh := t.identity.ConfigForAny()
	conn, err := dtls.Server(insecure, config)
	if err != nil {
		return nil, err
	}
	return t.handshake(ctx, conn, keyCh)
}

// SecureOutbound runs the TLS handshake as a client.
func (t *Transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	config, keyCh := t.identity.ConfigForPeer(p)
	conn, err := dtls.Client(insecure, config)
	if err != nil {
		return nil, err
	}
	return t.handshake(ctx, conn, keyCh)
}

func (t *Transport) handshake(
	ctx context.Context,
	tlsConn *dtls.Conn,
	keyCh <-chan ci.PubKey,
) (sec.SecureConn, error) {
	// There's no way to pass a context to tls.Conn.Handshake().
	// See https://github.com/golang/go/issues/18482.
	// Close the connection instead.
	select {
	case <-ctx.Done():
		tlsConn.Close()
	default:
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
			tlsConn.Close()
		}
	}()

	// Should be ready by this point, don't block.
	var remotePubKey ci.PubKey
	select {
	case remotePubKey = <-keyCh:
	default:
	}

	conn, err := t.setupConn(tlsConn, remotePubKey)
	if err != nil {
		// if the context was canceled, return the context error
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	return conn, nil
}

func (t *Transport) setupConn(tlsConn *dtls.Conn, remotePubKey ci.PubKey) (sec.SecureConn, error) {
	if remotePubKey == nil {
		return nil, errors.New("go-libp2p-dtls BUG: expected remote pub key to be set")
	}

	remotePeerID, err := peer.IDFromPublicKey(remotePubKey)
	if err != nil {
		return nil, err
	}
	return &conn{
		Conn:         tlsConn,
		localPeer:    t.localPeer,
		privKey:      t.privKey,
		remotePeer:   remotePeerID,
		remotePubKey: remotePubKey,
	}, nil
}