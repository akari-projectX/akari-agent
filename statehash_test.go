package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"slices"
	"strings"
	"testing"
)

// hashRecord is one (user, inbound) credential as tests and the shared
// vectors describe it.
type hashRecord struct {
	UserID   string
	Tag      string
	Protocol string
	Account  string // account_json verbatim
}

// stateHashRecords hashes records unique per (user_id, inbound_tag) with
// the production function.
func stateHashRecords(configVersion uint64, inboundsJSON string, recs []hashRecord) string {
	applied := make(map[string]map[string]appliedCred)
	for _, r := range recs {
		if applied[r.UserID] == nil {
			applied[r.UserID] = make(map[string]appliedCred)
		}
		applied[r.UserID][r.Tag] = appliedCred{protocol: r.Protocol, account: r.Account}
	}
	return stateHash(configVersion, inboundsJSON, applied)
}

// stateHashReference is the previous implementation (one sort over all
// records by (user_id, inbound_tag)), kept as the reference the faster
// ordering is checked against.
func stateHashReference(configVersion uint64, inboundsJSON string, recs []hashRecord) string {
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

// The per-user ordering must produce exactly the byte stream of the single
// (user_id, inbound_tag) sort, including ids that are prefixes of each
// other, empty strings and bytes above 0x7f (bytewise, not rune, order).
func TestStateHashMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := []string{"", "a", "b", "ab", "a#1", "a#10", "a#2", "\xff", "é", "A", "0"}
	pick := func() string {
		var b strings.Builder
		for range rng.Intn(4) {
			b.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		return b.String()
	}
	for i := range 500 {
		applied := make(map[string]map[string]appliedCred)
		var recs []hashRecord
		for range rng.Intn(60) {
			uid := pick()
			if applied[uid] == nil {
				applied[uid] = make(map[string]appliedCred)
			}
			for range rng.Intn(4) {
				tag := pick()
				if _, dup := applied[uid][tag]; dup {
					continue
				}
				c := appliedCred{protocol: pick(), account: pick()}
				applied[uid][tag] = c
				recs = append(recs, hashRecord{UserID: uid, Tag: tag, Protocol: c.protocol, Account: c.account})
			}
		}
		rng.Shuffle(len(recs), func(i, j int) { recs[i], recs[j] = recs[j], recs[i] })
		ver, inb := rng.Uint64(), pick()
		if got, want := stateHash(ver, inb, applied), stateHashReference(ver, inb, recs); got != want {
			t.Fatalf("case %d (%d records): stateHash = %s, want %s", i, len(recs), got, want)
		}
	}
}
