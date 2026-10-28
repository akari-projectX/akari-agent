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

	"google.golang.org/protobuf/encoding/protowire"
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
//
// CPU: a tick on which no counter moved and the final queue did not change
// writes nothing and encodes nothing (one read per counter). Otherwise the
// payload is appended with protowire into one reused buffer, and the final
// reports' part of it is re-encoded only when the queue changed. The bytes
// are exactly what proto.Marshal produces (TestCheckpointEncodingIsProto),
// so decodeReports reads files of either encoder.

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
	// onDisk: a slot holds a checkpoint (written since the last clear).
	// dirty: the next tick writes even if nothing changed (the last write
	// failed, or the slots were cleared).
	onDisk, dirty bool
	// finals is the encoded final-report part of the payload for version
	// finalsVer of the final queue.
	finals    []byte
	finalsVer uint64
	rows      []checkpointRow // reused for counters
	frame     []byte          // reused: header + payload
}

func (c *checkpointStore) path(i int) string { return filepath.Join(c.dir, checkpointSlots[i]) }

// The payload is a sequence of length-prefixed (uvarint) protobuf
// TrafficReports. appendReport appends one, field by field in the order
// and with the omissions of proto.Marshal (agent.proto TrafficReport and
// UserTraffic; proto3 leaves zero scalars and empty strings out).
func appendReport(b []byte, session string, monotonicMs uint64, rows []checkpointRow) []byte {
	n := 0
	for _, r := range rows {
		n += protowire.SizeTag(1) + protowire.SizeBytes(userTrafficSize(r))
	}
	if monotonicMs != 0 {
		n += protowire.SizeTag(2) + protowire.SizeVarint(monotonicMs)
	}
	if session != "" {
		n += protowire.SizeTag(3) + protowire.SizeBytes(len(session))
	}
	b = protowire.AppendVarint(b, uint64(n))
	for _, r := range rows {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendVarint(b, uint64(userTrafficSize(r)))
		if r.userID != "" {
			b = protowire.AppendTag(b, 1, protowire.BytesType)
			b = protowire.AppendString(b, r.userID)
		}
		if r.up != 0 {
			b = protowire.AppendTag(b, 2, protowire.VarintType)
			b = protowire.AppendVarint(b, r.up)
		}
		if r.down != 0 {
			b = protowire.AppendTag(b, 3, protowire.VarintType)
			b = protowire.AppendVarint(b, r.down)
		}
	}
	if monotonicMs != 0 {
		b = protowire.AppendTag(b, 2, protowire.VarintType)
		b = protowire.AppendVarint(b, monotonicMs)
	}
	if session != "" {
		b = protowire.AppendTag(b, 3, protowire.BytesType)
		b = protowire.AppendString(b, session)
	}
	return b
}

// userTrafficSize is the encoded size of one UserTraffic message.
func userTrafficSize(r checkpointRow) int {
	n := 0
	if r.userID != "" {
		n += protowire.SizeTag(1) + protowire.SizeBytes(len(r.userID))
	}
	if r.up != 0 {
		n += protowire.SizeTag(2) + protowire.SizeVarint(r.up)
	}
	if r.down != 0 {
		n += protowire.SizeTag(3) + protowire.SizeVarint(r.down)
	}
	return n
}

// appendReports appends reports (the final queue) to b; rows is scratch.
func appendReports(b []byte, reports []*pb.TrafficReport, rows []checkpointRow) ([]byte, []checkpointRow) {
	for _, r := range reports {
		rows = rows[:0]
		for _, u := range r.Users {
			rows = append(rows, checkpointRow{userID: u.UserId, up: u.UpBytes, down: u.DownBytes})
		}
		b = appendReport(b, r.SessionId, r.MonotonicMs, rows)
	}
	return b, rows
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
	c.onDisk = true
	reports, err := decodeReports(best)
	if err != nil {
		slog.Error("traffic checkpoint unreadable; dropping it", "error", err)
		return nil
	}
	return reports
}

// write stores frame (checkpointHdr bytes of room for the header, then the
// payload) in the older slot (in place, no fsync). The header is filled in
// place.
func (c *checkpointStore) write(frame []byte) error {
	payload := frame[checkpointHdr:]
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
	copy(frame, checkpointMagic)
	h := frame[len(checkpointMagic):]
	binary.BigEndian.PutUint64(h[0:8], c.seq)
	binary.BigEndian.PutUint32(h[8:12], uint32(len(payload)))
	binary.BigEndian.PutUint32(h[12:16], crc32.Checksum(payload, crcTable))
	if _, err := c.files[i].WriteAt(frame, 0); err != nil {
		return err
	}
	return c.files[i].Truncate(int64(len(frame)))
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
	c.onDisk = false
	c.dirty = true
}

// checkpointLocked writes what the agent owes the panel: the current
// instance's cumulative counters and every unconfirmed final report.
// Caller holds applyMu (the only path that moves counters from the
// instance into the final queue), so nothing is in neither.
//
// Nothing is encoded or written when no counter moved, the final queue is
// unchanged and the last write succeeded; a payload that is empty while
// no slot exists is not written either.
func (a *Agent) checkpointLocked() {
	c := a.ckpt
	if c == nil {
		return
	}
	finalsChanged := false
	if reports, ver, ok := a.finals.changedSince(c.finalsVer); ok {
		c.finals, c.rows = appendReports(c.finals[:0], reports, c.rows)
		c.finalsVer, finalsChanged = ver, true
	}
	session, rows, countersChanged := a.core.CheckpointCounters(c.rows[:0])
	c.rows = rows
	if !finalsChanged && !countersChanged && !c.dirty {
		return
	}
	c.frame = append(c.frame[:0], make([]byte, checkpointHdr)...)
	c.frame = append(c.frame, c.finals...)
	if len(rows) > 0 {
		c.frame = appendReport(c.frame, session, 0, rows)
	}
	if len(c.frame) == checkpointHdr && !c.onDisk {
		c.dirty = false
		return
	}
	if err := c.write(c.frame); err != nil {
		c.dirty = true
		slog.Error("cannot write traffic checkpoint", "error", err)
		return
	}
	c.onDisk, c.dirty = true, false
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
