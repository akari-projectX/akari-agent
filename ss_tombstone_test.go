package main

// W9: Shadowsocks 2022 removal without a rebuild. A removed user's
// credential stays in xray's multi-user table as a gate-refused tombstone,
// so the service's user indices never move. These tests drive real SS2022
// handshakes (sing-shadowsocks client, the library xray's own server uses)
// that stall right after the fixed header — the server has resolved the
// user index and waits for the variable header — across removals, and run
// under -race (`make test`).
//
// With xray's RemoveUser (swap-delete) a stalled handshake of a removed
// user resumes as whichever user moved into its slot (admitted and billed
// as them) or indexes past the end and panics the agent; here it must
// resolve to its own tombstone and be refused, while every other user's
// handshakes and established connections carry on.

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"

	"akari/agent/pb"
)

// stallConn delivers the first Write in two parts: the SS2022 fixed
// request header chunk (salt, identity header, fixed chunk), then — once
// release is closed — the rest (variable header and payload).
type stallConn struct {
	net.Conn
	split   int
	release <-chan struct{}
	first   sync.Once
	sent    chan struct{} // closed once the first part is on the wire
}

func (c *stallConn) Write(b []byte) (int, error) {
	n := 0
	var err error
	done := false
	c.first.Do(func() {
		done = true
		if len(b) <= c.split {
			close(c.sent)
			n, err = c.Conn.Write(b)
			return
		}
		var k int
		k, err = c.Conn.Write(b[:c.split])
		n += k
		close(c.sent)
		if err != nil {
			return
		}
		<-c.release
		k, err = c.Conn.Write(b[c.split:])
		n += k
	})
	if done {
		return n, err
	}
	return c.Conn.Write(b)
}

type ssEnv struct {
	method string
	psk    string
	port   int
	echo   int
	keyLen int
}

// handshake opens an SS2022 connection for userKey whose request stalls
// after the fixed header until release is closed. The returned channel is
// closed once the first part was written.
func (e *ssEnv) handshake(t *testing.T, userKey string, release <-chan struct{}) (net.Conn, <-chan struct{}) {
	t.Helper()
	method, err := shadowaead_2022.NewWithPassword(e.method, e.psk+":"+userKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", e.port))
	if err != nil {
		t.Fatal(err)
	}
	// salt + identity header + AEAD(fixed chunk: type, timestamp, length).
	sc := &stallConn{Conn: raw, split: e.keyLen + 16 + 11 + 16, release: release, sent: make(chan struct{})}
	return method.DialEarlyConn(sc, M.ParseSocksaddrHostPort("127.0.0.1", uint16(e.echo))), sc.sent
}

// exchange writes payload (carried by the request header on the first
// call) and reads it back. Sequential: the client must have written its
// request before it reads the response (and payloads here are small).
func exchange(c net.Conn, payload []byte) error {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("echo mismatch")
	}
	return nil
}

func newSSEnv(t *testing.T, users int) (*ssEnv, *CoreManager, []*pb.UserOp, string) {
	t.Helper()
	e := &ssEnv{method: "2022-blake3-aes-128-gcm", psk: b64key(16, 1), port: freePort(t), echo: echoServer(t), keyLen: 16}
	inb := "[" + ssInbound("ss", e.port, e.method, e.psk, true) + "]"
	ops := make([]*pb.UserOp, users)
	for i := range ops {
		ops[i] = ssOp(fmt.Sprintf("user-%02d", i), "ss", b64key(16, byte(0x20+i)))
	}
	m := NewCoreManager()
	t.Cleanup(func() { m.Teardown() })
	if _, err := m.Rebuild(inb, ops); err != nil {
		t.Fatal(err)
	}
	return e, m, ops, inb
}

func ssKeyOf(op *pb.UserOp) string { return b64keyFromAccount(op.InboundUsers[0].AccountJson) }

func b64keyFromAccount(acc string) string {
	var k string
	if _, err := fmt.Sscanf(acc, `{"password":%q}`, &k); err != nil {
		panic(err)
	}
	return k
}

func countersByUser(m *CoreManager) map[string][2]uint64 {
	out := map[string][2]uint64{}
	if rep := m.TrafficSnapshot(); rep != nil {
		for _, u := range rep.Users {
			out[u.UserId] = [2]uint64{u.UpBytes, u.DownBytes}
		}
	}
	return out
}

// Deterministic: every user has a handshake stalled past user resolution
// while some users are removed (one delta, no rebuild). Removed users'
// handshakes are refused; the others' complete as themselves; an
// established connection survives; per-user counters are exact (nothing
// billed to the wrong user). Then the removed users are re-added with the
// same keys (tombstones revived) and connect again.
func TestSS2022TombstoneStalledHandshakes(t *testing.T) {
	const users = 8
	e, m, ops, inb := newSSEnv(t, users)
	uid := func(i int) string { return ops[i].UserId }
	removed := map[int]bool{0: true, 2: true, 4: true}
	sent := map[string]uint64{}

	// An established connection of a user that stays.
	est, _ := e.handshake(t, ssKeyOf(ops[1]), closedChan())
	defer est.Close()
	if err := exchange(est, bytes.Repeat([]byte("e"), 100)); err != nil {
		t.Fatalf("established connection: %v", err)
	}
	sent[uid(1)] += 100

	release := make(chan struct{})
	results := make([]chan error, users)
	for i := range results {
		c, on := e.handshake(t, ssKeyOf(ops[i]), release)
		defer c.Close()
		results[i] = make(chan error, 1)
		go func(c net.Conn, n int) { results[n] <- exchange(c, bytes.Repeat([]byte{'a' + byte(n)}, 1000+n)) }(c, i)
		<-on
	}
	// The server has read the fixed headers (resolved the user indices)
	// and now waits for the variable headers.
	time.Sleep(300 * time.Millisecond)

	var rm []*pb.UserOp
	for i := range removed {
		rm = append(rm, &pb.UserOp{Op: pb.UserOp_REMOVE, UserId: uid(i)})
	}
	if m.WouldShrinkUnsafe(rm) {
		t.Fatal("SS2022 removal refused")
	}
	session := m.SessionID()
	if _, err := m.ApplyUserOps(rm); err != nil {
		t.Fatal(err)
	}
	if m.SessionID() != session || m.Tombstones("ss") != len(removed) {
		t.Fatalf("removal rebuilt or lost tombstones (tombstones %d)", m.Tombstones("ss"))
	}
	// The state hash is the remaining users only.
	var keep []*pb.UserOp
	for i, op := range ops {
		if !removed[i] {
			keep = append(keep, op)
		}
	}
	ref := NewCoreManager()
	defer ref.Teardown()
	if _, err := ref.Rebuild(swapPort(t, inb, e.port), keep); err != nil {
		t.Fatal(err)
	}
	if m.StateHash(1) != stateHash(1, inb, hashRecordsOf(ref)) {
		t.Fatal("state hash includes tombstones")
	}

	close(release)
	for i, res := range results {
		err := <-res
		switch {
		case removed[i] && err == nil:
			t.Fatalf("removed user %d: stalled handshake relayed after removal", i)
		case !removed[i] && err != nil:
			t.Fatalf("user %d: stalled handshake failed: %v", i, err)
		case !removed[i]:
			sent[uid(i)] += uint64(1000 + i)
		}
	}
	if err := exchange(est, []byte("still-here")); err != nil {
		t.Fatalf("established connection of a kept user cut by the removal: %v", err)
	}
	sent[uid(1)] += 10

	got := countersByUser(m)
	for i := 0; i < users; i++ {
		u := uid(i)
		if got[u] != [2]uint64{sent[u], sent[u]} {
			t.Fatalf("user %d counters %v, relayed %d each way", i, got[u], sent[u])
		}
	}

	// Re-add (same keys): the tombstones revive in place, no rebuild.
	var readd []*pb.UserOp
	for i := range removed {
		readd = append(readd, ops[i])
	}
	if m.WouldShrinkUnsafe(readd) {
		t.Fatal("re-add of the same SS keys refused")
	}
	if _, err := m.ApplyUserOps(readd); err != nil {
		t.Fatal(err)
	}
	if m.SessionID() != session || m.Tombstones("ss") != 0 || m.UserCount() != users {
		t.Fatalf("re-add: tombstones %d users %d", m.Tombstones("ss"), m.UserCount())
	}
	for i := range removed {
		c, _ := e.handshake(t, ssKeyOf(ops[i]), closedChan())
		if err := exchange(c, []byte("back")); err != nil {
			t.Fatalf("re-added user %d cannot connect: %v", i, err)
		}
		c.Close()
	}
	if err := exchange(est, []byte("still-here")); err != nil {
		t.Fatalf("established connection cut by the re-add: %v", err)
	}
}

// Concurrent: handshakes of every user stall for random times while a
// subset is removed and re-added over and over (deltas, tombstones). Users
// never touched never fail, their established connection survives, and
// their counters are exact; nothing panics; -race is clean.
func TestSS2022TombstoneRace(t *testing.T) {
	const users = 8
	e, m, ops, _ := newSSEnv(t, users)
	toggled := map[int]bool{0: true, 3: true, 5: true, 7: true}
	var mu sync.Mutex
	sent := map[string]uint64{}
	attempted := map[string]uint64{}

	est, _ := e.handshake(t, ssKeyOf(ops[1]), closedChan())
	defer est.Close()
	if err := exchange(est, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	sent[ops[1].UserId] += 5

	stop := make(chan struct{})
	var toggles atomic.Int32
	var tw sync.WaitGroup
	tw.Add(1)
	go func() {
		defer tw.Done()
		r := rand.New(rand.NewSource(1))
		var rm, add []*pb.UserOp
		for i := range toggled {
			rm = append(rm, &pb.UserOp{Op: pb.UserOp_REMOVE, UserId: ops[i].UserId})
			add = append(add, ops[i])
		}
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, batch := range [][]*pb.UserOp{rm, add} {
				if m.WouldShrinkUnsafe(batch) {
					t.Error("toggle refused")
					return
				}
				if _, err := m.ApplyUserOps(batch); err != nil {
					t.Error(err)
					return
				}
				time.Sleep(time.Duration(r.Intn(3000)) * time.Microsecond)
			}
			toggles.Add(1)
		}
	}()

	var wg sync.WaitGroup
	var refused, admitted atomic.Int32
	for w := 0; w < 12; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(int64(100 + w)))
			for it := 0; it < 15; it++ {
				i := r.Intn(users)
				u := ops[i].UserId
				release := make(chan struct{})
				c, on := e.handshake(t, ssKeyOf(ops[i]), release)
				payload := bytes.Repeat([]byte{byte(w)}, 200+r.Intn(800))
				res := make(chan error, 1)
				go func() { res <- exchange(c, payload) }()
				<-on
				time.Sleep(time.Duration(r.Intn(15)) * time.Millisecond)
				close(release)
				err := <-res
				c.Close()
				mu.Lock()
				attempted[u] += uint64(len(payload))
				if err == nil {
					sent[u] += uint64(len(payload))
				}
				mu.Unlock()
				switch {
				case err != nil && !toggled[i]:
					t.Errorf("user %d (never removed) failed: %v", i, err)
				case err != nil:
					refused.Add(1)
				case toggled[i]:
					admitted.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	tw.Wait()
	if err := exchange(est, []byte("survived")); err != nil {
		t.Fatalf("established connection of an untouched user cut: %v", err)
	}
	sent[ops[1].UserId] += 8
	t.Logf("toggles %d; toggled users: %d admitted, %d refused", toggles.Load(), admitted.Load(), refused.Load())

	// Leave the toggled users removed, then compare counters: untouched
	// users exactly what they relayed; toggled ones never more than they
	// sent (a cut connection may count a partial echo).
	got := countersByUser(m)
	for i := 0; i < users; i++ {
		u := ops[i].UserId
		if !toggled[i] {
			if got[u] != [2]uint64{sent[u], sent[u]} {
				t.Fatalf("untouched user %d counters %v, relayed %d each way", i, got[u], sent[u])
			}
		} else if got[u][0] > attempted[u] || got[u][1] > attempted[u] {
			t.Fatalf("toggled user %d counters %v exceed the %d bytes it sent", i, got[u], attempted[u])
		}
	}
	if m.Tombstones("ss") != 0 {
		t.Fatalf("%d tombstones after the last re-add", m.Tombstones("ss"))
	}
}

func closedChan() <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

// swapPort gives inb (one inbound on port) a fresh port, for a reference
// instance next to the one under test.
func swapPort(t *testing.T, inb string, port int) string {
	return string(bytes.Replace([]byte(inb), []byte(fmt.Sprintf(`"port":%d`, port)), []byte(fmt.Sprintf(`"port":%d`, freePort(t))), 1))
}

func hashRecordsOf(m *CoreManager) []hashRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	var recs []hashRecord
	for uid, tags := range m.applied {
		for tag, c := range tags {
			recs = append(recs, hashRecord{UserID: uid, Tag: tag, Protocol: c.protocol, Account: c.account})
		}
	}
	return recs
}
