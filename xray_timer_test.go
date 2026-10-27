//go:build canary

package main

import (
	"context"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/signal"
)

// Regression test for an upstream bug in xray (common/signal/timer.go,
// unfixed on XTLS/Xray-core main on 2026-10-27): SetTimeout holds the
// timer's lock while Periodic.Start runs the first check synchronously. If
// a check of the task SetTimeout just replaced runs at that moment, it
// takes the activity token the synchronous one expects, the synchronous
// check calls finish, and finish locks the mutex SetTimeout holds: the
// calling goroutine hangs for good. xray calls SetTimeout from the
// deferred end of both copy tasks of a connection (trojan, VMess,
// Shadowsocks 2022, freedom), so the connection's handler never returns:
// its socket stays open and, after a Rebuild, the goroutine's stack keeps
// the old xray instance alive. The 60-minute soak of 2026-10-27 lost 77
// handlers (goroutines 186 vs 43 after the drain, fds 93 vs 24).
//
// go.mod replaces xray-core with the akari-projectX/xray-core fork, which
// drains the token in the synchronous run instead of calling check. The
// test aims SetTimeout at the moment the previous task's check fires; on
// stock xray an 8 s run hangs a call about three times in four, with the
// fork never. Upstream declined the fix (2026-10-27), so the fork stays:
// every xray upgrade carries the patch to a new fork branch and runs this
// test (README "xray-core 分支"). Drop the replace only if a stock release
// passes it without the patch.
func TestXrayActivityTimerSelfDeadlock(t *testing.T) {
	const interval = 4 * time.Millisecond
	var hung atomic.Int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 512)
	trials := 0
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline) && hung.Load() == 0; trials++ {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			timer := signal.CancelAfterInactivity(ctx, cancel, 5*time.Minute)
			timer.SetTimeout(interval) // the first direction of a connection ended
			// The second one ends just as that task's check is due.
			time.Sleep(interval - 100*time.Microsecond + time.Duration(rand.IntN(200))*time.Microsecond)
			done := make(chan struct{})
			go func() { timer.SetTimeout(interval); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				hung.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := hung.Load(); n > 0 {
		t.Fatalf("xray's ActivityTimer.SetTimeout self-deadlocked (%d of %d trials): the linked xray lacks the fix (go.mod replace?)", n, trials)
	}
	t.Logf("no self-deadlock in %d aimed trials", trials)
}
