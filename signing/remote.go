package signing

import (
	"context"
	"errors"
)

// RemoteSigner is the seam every service uses to sign without holding a raw
// private key. Implementations may keep the key in-process (NewLocalSigner)
// or delegate to an external signer such as the OpenBao plugin.
type RemoteSigner interface {
	Address() string
	PublicKey() []byte
	SignDirect(ctx context.Context, req SignRequest) (SignedTransaction, error)
	SignMessage(ctx context.Context, envelope MessageEnvelope) (SignedMessage, error)
}

type localSigner struct {
	privateKey []byte
	publicKey  []byte
	address    string
}

// NewLocalSigner wraps the existing direct signing primitives behind the
// RemoteSigner interface. The private key is copied so later mutations of the
// caller's slice cannot change the signer's identity.
func NewLocalSigner(privateKey []byte) (RemoteSigner, error) {
	if len(privateKey) == 0 {
		return nil, errors.New("private key is required")
	}
	key := append([]byte(nil), privateKey...)
	pub, err := publicKeyForPrivateKey(key)
	if err != nil {
		return nil, err
	}
	address, err := Address(pub, DefaultAddressPrefix)
	if err != nil {
		return nil, err
	}
	return &localSigner{privateKey: key, publicKey: pub, address: address}, nil
}

func (s *localSigner) Address() string { return s.address }

func (s *localSigner) PublicKey() []byte {
	return append([]byte(nil), s.publicKey...)
}

func (s *localSigner) SignDirect(ctx context.Context, req SignRequest) (SignedTransaction, error) {
	if err := ctx.Err(); err != nil {
		return SignedTransaction{}, err
	}
	return SignTransaction(s.privateKey, req)
}

func (s *localSigner) SignMessage(ctx context.Context, envelope MessageEnvelope) (SignedMessage, error) {
	if err := ctx.Err(); err != nil {
		return SignedMessage{}, err
	}
	return SignMessage(s.privateKey, envelope)
}

// publicKeyForPrivateKey derives the compressed public key in the core.
func publicKeyForPrivateKey(privateKey []byte) ([]byte, error) {
	var out struct {
		PublicKey string `json:"public_key_base64"`
	}
	if err := call("signing.public_key", map[string]string{"private_key_base64": b64(privateKey)}, &out); err != nil {
		return nil, err
	}
	return unb64("public_key", out.PublicKey)
}
