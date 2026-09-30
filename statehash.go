package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
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
func stateHash(configVersion uint64, inboundsJSON string, recs []hashRecord) string {
	sorted := append([]hashRecord(nil), recs...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].UserID != sorted[j].UserID {
			return sorted[i].UserID < sorted[j].UserID
		}
		return sorted[i].Tag < sorted[j].Tag
	})
	h := sha256.New()
	h.Write([]byte("akari-state-v2\n"))
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], configVersion)
	h.Write(b8[:])
	var b4 [4]byte
	field := func(s string) {
		binary.BigEndian.PutUint32(b4[:], uint32(len(s)))
		h.Write(b4[:])
		h.Write([]byte(s))
	}
	for _, r := range sorted {
		field(r.UserID)
		field(r.Tag)
		field(r.Protocol)
		field(r.Account)
	}
	inb := sha256.Sum256([]byte(inboundsJSON))
	field(string(inb[:]))
	return hex.EncodeToString(h.Sum(nil))
}
