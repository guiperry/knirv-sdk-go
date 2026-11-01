package authority

import (
	"encoding/binary"
	"encoding/hex"
)

// Header is the 80-byte proof-of-work header:
//
//	version/tier(4) || prevhash=action_digest(32) ||
//	merkle=prev_record_hash(32) || ntime(4) || nbits(4) || nonce(4)
type Header [80]byte

type headerReply struct {
	Header      string `json:"header"`
	Witness     string `json:"witness"`
	MeetsTarget bool   `json:"meets_target"`
	Nonce       uint32 `json:"nonce"`
}

func headerRequest(prevHash, merkle [32]byte, ntime, nbits uint32, version uint8, tier Tier) map[string]any {
	return map[string]any{
		"prev_hash": hex.EncodeToString(prevHash[:]), "merkle": hex.EncodeToString(merkle[:]),
		"ntime": ntime, "nbits": nbits, "version": version, "tier": uint8(tier),
	}
}

func decodeHeader(text string) (h Header) {
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != len(h) {
		panic("authority: native core returned a malformed header")
	}
	copy(h[:], raw)
	return h
}

// NewHeader assembles a header and writes the supplied nonce.
func NewHeader(prevHash, merkle [32]byte, ntime, nbits, nonce uint32, version uint8, tier Tier) Header {
	request := headerRequest(prevHash, merkle, ntime, nbits, version, tier)
	request["nonce"] = nonce
	var out headerReply
	mustCall("authority.header", request, &out)
	return decodeHeader(out.Header)
}

func (h Header) VersionTier() uint32 { return binary.BigEndian.Uint32(h[0:4]) }
func (h Header) Version() uint8      { return uint8(h.VersionTier() >> 8) }
func (h Header) Tier() Tier          { return Tier(h.VersionTier() & 0xff) }
func (h Header) PrevHash() (out [32]byte) {
	copy(out[:], h[4:36])
	return out
}
func (h Header) Merkle() (out [32]byte) {
	copy(out[:], h[36:68])
	return out
}
func (h Header) NTime() uint32 { return binary.BigEndian.Uint32(h[68:72]) }
func (h Header) NBits() uint32 { return binary.BigEndian.Uint32(h[72:76]) }
func (h Header) Nonce() uint32 { return binary.BigEndian.Uint32(h[76:80]) }

// Bytes returns the serialized header.
func (h Header) Bytes() []byte { return h[:] }

func (h Header) reply() headerReply {
	request := headerRequest(h.PrevHash(), h.Merkle(), h.NTime(), h.NBits(), h.Version(), h.Tier())
	request["nonce"] = h.Nonce()
	var out headerReply
	mustCall("authority.header", request, &out)
	return out
}

// Witness returns sha256d(header), the value compared with the target.
func (h Header) Witness() [32]byte { return decode32(h.reply().Witness) }

// Hash is the same 32 bytes as Witness().
func (h Header) Hash() [32]byte { return h.Witness() }

// MeetsTarget reports whether witness is at or below the compact target,
// interpreting the witness as Bitcoin's little-endian uint256.
func MeetsTarget(witness [32]byte, bits uint32) bool {
	var out headerReply
	mustCall("authority.meets_target", map[string]any{"witness": hex.EncodeToString(witness[:]), "nbits": bits}, &out)
	return out.MeetsTarget
}

// Mine searches for a header nonce that satisfies bits. It starts at
// startNonce and fails after the full 32-bit nonce space is exhausted.
func Mine(prevHash, merkle [32]byte, ntime, nbits, startNonce uint32, version uint8, tier Tier) (Header, uint32, error) {
	request := headerRequest(prevHash, merkle, ntime, nbits, version, tier)
	request["start_nonce"] = startNonce
	var out headerReply
	if err := call("authority.mine_header", request, &out); err != nil {
		return Header{}, 0, err
	}
	return decodeHeader(out.Header), out.Nonce, nil
}
