package main

// Audit 2026-10 P3-19: does xray v26.10.21 still need the SS2022 tombstone
// mechanism (ss_tombstone_test.go)? These tests do what the agent must not
// do: they remove users from the multi-user inbound with xray's own
// RemoveUser (and re-add them with AddUser) while handshakes are stalled
// after the user was resolved, and assert the properties the tombstones
// exist for: a removed user's stalled handshake is refused (not admitted as
// someone else), the other users' handshakes complete as themselves,
// counters are exact, nothing panics (-race).
//
// Finding: with this xray they pass. The multi-user server resolves the
// user through a map keyed by the user's PSK hash and keeps that user's
// own *MemoryUser for the connection; RemoveUser deletes map entries and
// moves nobody (proxy/shadowsocks_2022/inbound_multi.go), unlike the
// swap-delete of v26.3.27 these tombstones were built for. The mechanism is
// therefore unnecessary on this xray; it is kept until a follow-up removes
// it together with the panel's protocol-5 delta rules (CLAUDE.md).

import (
	"bytes"
	"context"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"akari/agent/pb"
)

// nativeRemove removes uid from the tag the way the agent does for every
// other protocol: revoke at the gate, then xray's RemoveUser.
func nativeRemove(t testing.TB, m *CoreManager, tag, uid string) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gate.Revoke(gateKey{tag: tag, email: uid})
	store, err := m.store(tag)
	if err != nil {
		t.Error(err)
		return
	}
	if err := store.RemoveUser(context.Background(), uid); err != nil {
		t.Errorf("RemoveUser(%s) error: %v", uid, err)
	}
}

// nativeAdd installs op's credential with a new *MemoryUser, as the agent
// does for every other protocol.
func nativeAdd(t testing.TB, m *CoreManager, op *pb.UserOp) {
	t.Helper()
	iu := op.InboundUsers[0]
	m.mu.Lock()
	defer m.mu.Unlock()
	user, err := buildUser(iu.Protocol, iu.AccountJson, op.UserId, m.kinds[iu.InboundTag])
	if err != nil {
		t.Error(err)
		return
	}
	mu, err := user.ToMemoryUser()
	if err != nil {
		t.Error(err)
		return
	}
	m.gate.Allow(gateKey{tag: iu.InboundTag, email: op.UserId}, mu)
	store, err := m.store(iu.InboundTag)
	if err != nil {
		t.Error(err)
		return
	}
	if err := store.AddUser(context.Background(), mu); err != nil {
		t.Errorf("AddUser(%s) error: %v", op.UserId, err)
	}
}

func TestSS2022NativeRemoveStalledHandshakes(t *testing.T) {
	const users = 8
	e, m, ops, _ := newSSEnv(t, users)
	removed := map[int]bool{0: true, 2: true, 4: true}
	sent := map[string]uint64{}

	est, _ := e.handshake(t, ssKeyOf(ops[1]), closedChan())
	defer est.Close()
	if err := exchange(est, bytes.Repeat([]byte("e"), 100)); err != nil {
		t.Fatalf("established connection: %v", err)
	}
	sent[ops[1].UserId] += 100

	release := make(chan struct{})
	results := make([]chan error, users)
	for i := range results {
		c, on := e.handshake(t, ssKeyOf(ops[i]), release)
		defer c.Close()
		results[i] = make(chan error, 1)
		go func(c net.Conn, n int) { results[n] <- exchange(c, bytes.Repeat([]byte{'a' + byte(n)}, 1000+n)) }(c, i)
		<-on
	}
	time.Sleep(300 * time.Millisecond) // the server has resolved the users
	for i := range removed {
		nativeRemove(t, m, "ss", ops[i].UserId)
	}
	close(release)
	for i, res := range results {
		err := <-res
		switch {
		case removed[i] && err == nil:
			t.Fatalf("removed user %d: stalled handshake relayed after RemoveUser", i)
		case !removed[i] && err != nil:
			t.Fatalf("user %d: stalled handshake failed after others were removed: %v", i, err)
		case !removed[i]:
			sent[ops[i].UserId] += uint64(1000 + i)
		}
	}
	if err := exchange(est, []byte("still-here")); err != nil {
		t.Fatalf("established connection of a kept user cut by RemoveUser: %v", err)
	}
	sent[ops[1].UserId] += 10
	got := countersByUser(m)
	for i := range users {
		u := ops[i].UserId
		if got[u] != [2]uint64{sent[u], sent[u]} {
			t.Errorf("user %d counters = %v, want %d each way", i, got[u], sent[u])
		}
	}
	// A removed user can come back with a new credential object, and a
	// changed key is just another AddUser (no snapshot needed).
	for i := range removed {
		nativeAdd(t, m, ops[i])
		c, _ := e.handshake(t, ssKeyOf(ops[i]), closedChan())
		if err := exchange(c, []byte("back")); err != nil {
			t.Errorf("re-added user %d cannot connect: %v", i, err)
		}
		c.Close()
	}
}

func TestSS2022NativeRemoveRace(t *testing.T) {
	const users = 8
	e, m, ops, _ := newSSEnv(t, users)
	toggled := map[int]bool{0: true, 3: true, 5: true, 7: true}
	var mu sync.Mutex
	sent := map[string]uint64{}

	est, _ := e.handshake(t, ssKeyOf(ops[1]), closedChan())
	defer est.Close()
	if err := exchange(est, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	sent[ops[1].UserId] += 5

	stop := make(chan struct{})
	var tw sync.WaitGroup
	tw.Add(1)
	go func() {
		defer tw.Done()
		r := rand.New(rand.NewSource(1))
		for {
			select {
			case <-stop:
				return
			default:
			}
			for i := range toggled {
				nativeRemove(t, m, "ss", ops[i].UserId)
			}
			time.Sleep(time.Duration(r.Intn(3000)) * time.Microsecond)
			for i := range toggled {
				nativeAdd(t, m, ops[i])
			}
			time.Sleep(time.Duration(r.Intn(3000)) * time.Microsecond)
		}
	}()
	var wg sync.WaitGroup
	var refused, admitted atomic.Int32
	for w := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := rand.New(rand.NewSource(int64(100 + w)))
			for range 15 {
				i := r.Intn(users)
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
				if err == nil {
					mu.Lock()
					sent[ops[i].UserId] += uint64(len(payload))
					mu.Unlock()
				}
				switch {
				case err != nil && !toggled[i]:
					t.Errorf("user %d (never removed) failed: %v", i, err)
				case err != nil:
					refused.Add(1)
				case toggled[i]:
					admitted.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	tw.Wait()
	if err := exchange(est, []byte("survived")); err != nil {
		t.Fatalf("established connection of an untouched user cut: %v", err)
	}
	sent[ops[1].UserId] += 8
	t.Logf("toggled users: %d admitted, %d refused", admitted.Load(), refused.Load())
	got := countersByUser(m)
	for i := range users {
		if toggled[i] {
			continue
		}
		u := ops[i].UserId
		if got[u] != [2]uint64{sent[u], sent[u]} {
			t.Errorf("untouched user %d counters = %v, want %d each way", i, got[u], sent[u])
		}
	}
}
