package signing

import (
	"errors"
	"math/big"
)

// secp256k1 group order n. A low-S signature has s <= n/2.
var (
	secp256k1Order, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secp256k1HalfOrder = new(big.Int).Rsh(secp256k1Order, 1)
)

// ErrHighS reports a signature whose s half is above n/2 (the high-S twin of a
// valid signature, s' = n - s).
var ErrHighS = errors.New("signing: signature s must be low-S (s <= n/2)")

// requireLowS rejects a 64-byte r||s signature whose s is above n/2 or zero. The
// core also rejects these; the binding repeats the check so it holds even when the
// loaded core artifact predates the core's explicit low-S check. Other lengths are
// left to the core, which reports them as encoding errors.
func requireLowS(signature []byte) error {
	if len(signature) != 64 {
		return nil
	}
	s := new(big.Int).SetBytes(signature[32:])
	if s.Sign() == 0 {
		return errors.New("signing: signature s must be non-zero")
	}
	if s.Cmp(secp256k1HalfOrder) > 0 {
		return ErrHighS
	}
	return nil
}
