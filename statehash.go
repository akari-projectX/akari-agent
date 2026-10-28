package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
)

// stateHash implements agent.proto "State hash" (v2): lowercase hex SHA-256
// over "akari-state-v2\n" || u64be(configVersion) || for each record sorted
// by (user_id, inbound_tag) bytewise: len-prefixed (u32be) user_id,
// inbound_tag, protocol, account_json || u32be(32) || SHA-256(inbounds
// JSON verbatim as sent; "" when nothing runs). The records are applied:
// user id -> inbound tag -> credential, so each (user_id, inbound_tag) is
// unique by construction. Test vectors: proto/state_hash_vectors.json.
//
// It runs on every Ack and Hello under applyMu. Sorting the user ids and
// then each user's few tags yields the (user_id, inbound_tag) order without
// sorting a slice of 20k four-string records (most of the cost before);
// each record is encoded into one reused scratch buffer (W2: no per-field
// []byte(s) copies).
func stateHash(configVersion uint64, inboundsJSON string, applied map[string]map[string]appliedCred) string {
	uids := make([]string, 0, len(applied))
	for uid := range applied {
		uids = append(uids, uid)
	}
	slices.Sort(uids)
	h := sha256.New()
	scratch := make([]byte, 0, 512)
	scratch = append(scratch, "akari-state-v2\n"...)
	scratch = binary.BigEndian.AppendUint64(scratch, configVersion)
	h.Write(scratch)
	field := func(b []byte, s string) []byte {
		b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
		return append(b, s...)
	}
	var tags []string
	for _, uid := range uids {
		creds := applied[uid]
		tags = tags[:0]
		for tag := range creds {
			tags = append(tags, tag)
		}
		slices.Sort(tags)
		for _, tag := range tags {
			c := creds[tag]
			scratch = field(scratch[:0], uid)
			scratch = field(scratch, tag)
			scratch = field(scratch, c.protocol)
			scratch = field(scratch, c.account)
			h.Write(scratch)
		}
	}
	inb := sha256.Sum256([]byte(inboundsJSON))
	scratch = binary.BigEndian.AppendUint32(scratch[:0], uint32(len(inb)))
	scratch = append(scratch, inb[:]...)
	h.Write(scratch)
	var sum [sha256.Size]byte
	return hex.EncodeToString(h.Sum(sum[:0]))
}
