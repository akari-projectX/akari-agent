package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/proto"

	pb "akari/agent/pb"
)

// Traffic checkpoint (crash safety of the counters).
//
// The periodic report only carries what xray counted up to the last tick, and
// finals.json is written only on a graceful stop. A process that dies hard
// (SIGKILL, OOM killer, a panic) used to lose every byte counted since the
// last report that reached the panel: one report interval normally, and
// everything since the disconnect while the panel was unreachable (live
// test 2026-10-10: Vision billed at 67%, a hard kill after a panel outage
// at 19%). So every checkpointEvery the agent writes what it owes the
// panel — the unconfirmed final reports and the current instance's
// cumulative counters — to the state directory, independent of the stream;
// the next process queues it as final reports (accounting is cumulative
// per session and idempotent, so resending already-billed values is
// harmless). A hard kill now loses at most one checkpoint interval.
//
// Disk wear: the checkpoint is rewritten in place in one of two slot files
// (alternating, each with a sequence number and a CRC) and never fsynced:
// the case it covers is the process dying, not the machine, and the page
// cache survives that. Rewriting the same file in place keeps the kernel's
// writeback to about one copy per dirty-expire period instead of one per
// write (no rename, no truncate-to-zero, so ext4's auto_da_alloc does not
// force a flush either). A slot torn by a kill mid-write fails its CRC and
// the other, older slot is used.

const (
	checkpointMagic = "AKCKPT01"
	checkpointHdr   = len(checkpointMagic) + 8 + 4 + 4 // magic, seq, len, crc
	// defaultCheckpointEvery: what a hard kill can lose at most.
	defaultCheckpointEvery = time.Second
	// maxCheckpointPayload bounds a checkpoint (the length field is 32
	// bits; ~1.3 M user rows at 50 bytes fit in 64 MiB, the agent's own
	// message limit).
	maxCheckpointPayload = 64 << 20
)

var checkpointSlots = [2]string{"traffic.ckpt.0", "traffic.ckpt.1"}

type checkpointStore struct {
	dir   string
	seq   uint64
	files [2]*os.File
	last  []byte // payload of the last write (unchanged = no write)
}

func (c *checkpointStore) path(i int) string { return filepath.Join(c.dir, checkpointSlots[i]) }

// encodeReports is the payload: length-prefixed protobuf TrafficReports.
func encodeReports(reports []*pb.TrafficReport) ([]byte, error) {
	var out []byte
	for _, r := range reports {
		b, err := proto.Marshal(r)
		if err != nil {
			return nil, err
		}
		out = binary.AppendUvarint(out, uint64(len(b)))
		out = append(out, b...)
	}
	return out, nil
}

func decodeReports(b []byte) ([]*pb.TrafficReport, error) {
	var out []*pb.TrafficReport
	for len(b) > 0 {
		n, k := binary.Uvarint(b)
		if k <= 0 || n > uint64(len(b)-k) {
			return nil, errors.New("truncated report")
		}
		var r pb.TrafficReport
		if err := proto.Unmarshal(b[k:k+int(n)], &r); err != nil {
			return nil, err
		}
		out = append(out, &r)
		b = b[k+int(n):]
	}
	return out, nil
}

// readSlot returns a slot's sequence number and payload (ok=false: missing,
// torn or foreign).
func readSlot(path string) (seq uint64, payload []byte, ok bool) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) < checkpointHdr || string(b[:len(checkpointMagic)]) != checkpointMagic {
		return 0, nil, false
	}
	h := b[len(checkpointMagic):]
	seq = binary.BigEndian.Uint64(h[0:8])
	n := binary.BigEndian.Uint32(h[8:12])
	sum := binary.BigEndian.Uint32(h[12:16])
	body := b[checkpointHdr:]
	if n > maxCheckpointPayload || uint64(n) != uint64(len(body)) || crc32.Checksum(body, crcTable) != sum {
		return 0, nil, false
	}
	return seq, body, true
}

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// load returns the reports of the newest intact slot (nil: none).
func (c *checkpointStore) load() []*pb.TrafficReport {
	var best []byte
	var bestSeq uint64
	found := false
	for i := range checkpointSlots {
		seq, body, ok := readSlot(c.path(i))
		if ok && seq > c.seq {
			c.seq = seq // a leftover slot must never outrank new writes
		}
		if ok && (!found || seq > bestSeq) {
			best, bestSeq, found = body, seq, true
		}
	}
	if !found {
		return nil
	}
	reports, err := decodeReports(best)
	if err != nil {
		slog.Error("traffic checkpoint unreadable; dropping it", "error", err)
		return nil
	}
	return reports
}

// write stores the payload in the older slot (in place, no fsync).
func (c *checkpointStore) write(payload []byte) error {
	if len(payload) > maxCheckpointPayload {
		return fmt.Errorf("checkpoint of %d bytes exceeds %d", len(payload), maxCheckpointPayload)
	}
	c.seq++
	i := int(c.seq % 2)
	if c.files[i] == nil {
		f, err := os.OpenFile(c.path(i), os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		c.files[i] = f
	}
	buf := make([]byte, checkpointHdr+len(payload))
	copy(buf, checkpointMagic)
	h := buf[len(checkpointMagic):]
	binary.BigEndian.PutUint64(h[0:8], c.seq)
	binary.BigEndian.PutUint32(h[8:12], uint32(len(payload)))
	binary.BigEndian.PutUint32(h[12:16], crc32.Checksum(payload, crcTable))
	copy(buf[checkpointHdr:], payload)
	if _, err := c.files[i].WriteAt(buf, 0); err != nil {
		return err
	}
	return c.files[i].Truncate(int64(len(buf)))
}

// clear removes both slots (their content has been handed on).
func (c *checkpointStore) clear() {
	for i := range checkpointSlots {
		if c.files[i] != nil {
			_ = c.files[i].Close()
			c.files[i] = nil
		}
		if err := os.Remove(c.path(i)); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("cannot remove traffic checkpoint", "error", err)
		}
	}
	c.last = nil
}

// checkpointLocked writes what the agent owes the panel: the current
// instance's cumulative counters and every unconfirmed final report.
// Caller holds applyMu (the only path that moves counters from the
// instance into the final queue), so nothing is in neither.
func (a *Agent) checkpointLocked() {
	if a.ckpt == nil {
		return
	}
	reports := a.finals.all()
	if snap := a.core.TrafficSnapshot(); snap != nil && len(snap.Users) > 0 {
		reports = append(reports, snap)
	}
	payload, err := encodeReports(reports)
	if err != nil {
		slog.Error("cannot encode traffic checkpoint", "error", err)
		return
	}
	if string(payload) == string(a.ckpt.last) {
		return
	}
	if err := a.ckpt.write(payload); err != nil {
		slog.Error("cannot write traffic checkpoint", "error", err)
		return
	}
	a.ckpt.last = payload
}

// checkpointLoop runs for the process lifetime. A tick on which applyMu is
// busy (a rebuild, an update) is skipped: the previous checkpoint stays.
func (a *Agent) checkpointLoop(ctx context.Context) {
	if a.ckpt == nil || a.checkpointEvery <= 0 {
		return
	}
	t := time.NewTicker(a.checkpointEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if a.applyMu.TryLock() {
			if !a.stopping.Load() {
				a.checkpointLocked()
			}
			a.applyMu.Unlock()
		}
	}
}

// resumeCheckpoint (process start): what a previous process left in its
// checkpoint becomes final reports, persisted with the other finals before
// the checkpoint is removed. Returns the number of reports recovered.
func (a *Agent) resumeCheckpoint() int {
	if a.ckpt == nil {
		return 0
	}
	reports := a.ckpt.load()
	if len(reports) == 0 {
		a.ckpt.clear()
		return 0
	}
	for _, r := range reports {
		a.finals.add(r)
	}
	if st := a.finalStore(); st != nil {
		if err := st.save(a.finals.all()); err != nil {
			// Keep the checkpoint: the next start tries again.
			slog.Error("cannot persist recovered traffic counters", "error", err)
			return len(reports)
		}
		a.finalsPersisted.Store(true)
	}
	a.ckpt.clear()
	return len(reports)
}
