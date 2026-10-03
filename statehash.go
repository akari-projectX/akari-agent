package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"strings"
)

// hashRecord is one applied (user, inbound) credential.
type hashRecord struct {
	UserID   string
	Tag      string
	Protocol string
	Account  string // account_json verbatim
}

// stateHash implements agent.proto "State hash" (v2): lowercase hex SHA-256
// over "akari-state-v2\n" || u64be(configVersion) || for each record sorted
// by (user_id, inbound_tag) bytewise: len-prefixed (u32be) user_id,
// inbound_tag, protocol, account_json || u32be(32) || SHA-256(inbounds
// JSON verbatim as sent; "" when nothing runs). Records must be unique per
// (user_id, inbound_tag). Test vectors: proto/state_hash_vectors.json.
//
// recs is sorted in place. Each record is encoded into one reused scratch
// buffer (W2: no per-field []byte(s) copies; 20k records hash with a
// constant number of allocations).
func stateHash(configVersion uint64, inboundsJSON string, recs []hashRecord) string {
	slices.SortFunc(recs, func(a, b hashRecord) int {
		if c := strings.Compare(a.UserID, b.UserID); c != 0 {
			return c
		}
		return strings.Compare(a.Tag, b.Tag)
	})
	h := sha256.New()
	scratch := make([]byte, 0, 512)
	scratch = append(scratch, "akari-state-v2\n"...)
	scratch = binary.BigEndian.AppendUint64(scratch, configVersion)
	h.Write(scratch)
	field := func(b []byte, s string) []byte {
		b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
		return append(b, s...)
	}
	for _, r := range recs {
		scratch = field(scratch[:0], r.UserID)
		scratch = field(scratch, r.Tag)
		scratch = field(scratch, r.Protocol)
		scratch = field(scratch, r.Account)
		h.Write(scratch)
	}
	inb := sha256.Sum256([]byte(inboundsJSON))
	scratch = binary.BigEndian.AppendUint32(scratch[:0], uint32(len(inb)))
	scratch = append(scratch, inb[:]...)
	h.Write(scratch)
	var sum [sha256.Size]byte
	return hex.EncodeToString(h.Sum(sum[:0]))
}
