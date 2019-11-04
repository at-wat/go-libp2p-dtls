package go_libp2p_dtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/pion/dtls"

	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
)

const certValidityPeriod = 100 * 365 * 24 * time.Hour // ~100 years
const certificatePrefix = "libp2p-tls-handshake:"

var extensionID = getPrefixedExtensionID([]int{1, 1})

type signedKey struct {
	PubKey    []byte
	Signature []byte
}

// Identity is used to secure connections
type Identity struct {
	config dtls.Config
}

// NewIdentity creates a new identity
func NewIdentity(privKey ic.PrivKey) (*Identity, error) {
	cert, certKey, err := keyToCertificate(privKey)
	if err != nil {
		return nil, err
	}
	return &Identity{
		config: dtls.Config{
			Certificate: cert,
			PrivateKey: certKey,
			ClientAuth: dtls.RequireAnyClientCert,
			InsecureSkipVerify: true, // This is not insecure here. We will verify the cert ourselves.
			//ExtendedMasterSecret: dtls.DisableExtendedMasterSecret,
			VerifyPeerCertificate: func(_ *x509.Certificate, _ bool) error {
			  panic("dtls config not specialized for peer")
			},
		},
	}, nil
}

// ConfigForAny is a short-hand for ConfigForPeer("").
func (i *Identity) ConfigForAny() (*dtls.Config, <-chan ic.PubKey) {
	return i.ConfigForPeer("")
}

// ConfigForPeer creates a new single-use tls.Config that verifies the peer's
// certificate chain and returns the peer's public key via the channel. If the
// peer ID is empty, the returned config will accept any peer.
//
// It should be used to create a new dtls.Config before securing either an
// incoming or outgoing connection.
func (i *Identity) ConfigForPeer(remote peer.ID) (*dtls.Config, <-chan ic.PubKey) {
	keyCh := make(chan ic.PubKey, 1)
	// We need to check the peer ID in the VerifyPeerCertificate callback.
	// The dtls.Config it is also used for listening, and we might also have concurrent dials.
	// Clone it so we can check for the specific peer ID we're dialing here.
	conf := dtls.Config{
		Certificate: i.config.Certificate,
		PrivateKey: i.config.PrivateKey,
		ClientAuth: i.config.ClientAuth,
		InsecureSkipVerify: i.config.InsecureSkipVerify,
		ExtendedMasterSecret: i.config.ExtendedMasterSecret,
	}

	// The pion DTLS handshake handler calls VerifyPeerCertificate multiple times,
	// so we guard against sending on a closed key channel
	sendOnce := sync.Once{}
	closeOnce := sync.Once{}

	// We're using InsecureSkipVerify, so the valid parameter will always be false.
	conf.VerifyPeerCertificate = func(peerCert *x509.Certificate, valid bool) error {
		defer closeOnce.Do(func () { close(keyCh) })

		pubKey, err := PubKeyFromCert(peerCert)
		if err != nil {
			return err
		}
		if remote != "" && !remote.MatchesPublicKey(pubKey) {
			return errors.New("peer IDs don't match")
		}
		sendOnce.Do(func () { keyCh <- pubKey })
		return nil
	}
	return &conf, keyCh
}

// PubKeyFromCert verifies the certificate and extract the remote's public key.
func PubKeyFromCert(cert *x509.Certificate) (ic.PubKey, error) {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		// If we return an x509 error here, it will be sent on the wire.
		// Wrap the error to avoid that.
		return nil, fmt.Errorf("certificate verification failed: %s", err)
	}

	var found bool
	var keyExt pkix.Extension
	// find the libp2p key extension, skipping all unknown extensions
	for _, ext := range cert.Extensions {
		if extensionIDEqual(ext.Id, extensionID) {
			keyExt = ext
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("expected certificate to contain the key extension")
	}
	var sk signedKey
	if _, err := asn1.Unmarshal(keyExt.Value, &sk); err != nil {
		return nil, fmt.Errorf("unmarshalling signed certificate failed: %s", err)
	}
	pubKey, err := ic.UnmarshalPublicKey(sk.PubKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling public key failed: %s", err)
	}
	certKeyPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	valid, err := pubKey.Verify(append([]byte(certificatePrefix), certKeyPub...), sk.Signature)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %s", err)
	}
	if !valid {
		return nil, errors.New("signature invalid")
	}
	return pubKey, nil
}

func keyToCertificate(sk ic.PrivKey) (*x509.Certificate, crypto.PrivateKey, error) {
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	keyBytes, err := ic.MarshalPublicKey(sk.GetPublic())
	if err != nil {
		return nil, nil, err
	}
	certKeyPub, err := x509.MarshalPKIXPublicKey(certKey.Public())
	if err != nil {
		return nil, nil, err
	}
	signature, err := sk.Sign(append([]byte(certificatePrefix), certKeyPub...))
	if err != nil {
		return nil, nil, err
	}
	value, err := asn1.Marshal(signedKey{
		PubKey:    keyBytes,
		Signature: signature,
	})
	if err != nil {
		return nil, nil, err
	}

	sn, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, err
	}

	origin := make([]byte, 16)


	template := x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		Version:               2,
		IsCA: true,
		SerialNumber: sn,
		NotBefore:    time.Time{},
		NotAfter:     time.Now().Add(certValidityPeriod),
		Subject:               pkix.Name{CommonName: hex.EncodeToString(origin)},
		//after calling CreateCertificate, these will end up in Certificate.Extensions
		ExtraExtensions: []pkix.Extension{
			{Id: extensionID, Value: value},
		},
	}

	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, &certKey.PublicKey, certKey)
	if err != nil {
		return nil, nil, err
	}

	finalCert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}

	return finalCert, certKey, nil
}
