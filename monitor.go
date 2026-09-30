package main

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"

	"akari/agent/pb"
)

func newSessionID() string {
	return uuid.NewString()
}

func heartbeatLoop(ctx context.Context, every time.Duration, send func(*pb.AgentUp) error, lease func() (time.Duration, bool)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	var lastCPU float64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		// cpu.Percent(0, ...) returns usage since the previous call.
		if pcts, err := cpu.Percent(0, false); err == nil && len(pcts) > 0 {
			lastCPU = pcts[0]
		}
		hb := &pb.Heartbeat{CpuPercent: lastCPU}
		if vm, err := mem.VirtualMemory(); err == nil {
			hb.MemUsedBytes = vm.Used
			hb.MemTotalBytes = vm.Total
		}
		if left, armed := lease(); armed {
			secs := uint64(left / time.Second)
			hb.LeaseRemainingSeconds = &secs
		}
		if err := send(&pb.AgentUp{Msg: &pb.AgentUp_Heartbeat{Heartbeat: hb}}); err != nil {
			return
		}
	}
}

// trafficLoop reports cumulative counters every interval; onTick runs after
// each tick on which the stream was still usable.
func trafficLoop(ctx context.Context, every time.Duration, cm *CoreManager, send func(*pb.AgentUp) error, onTick func()) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		report := cm.TrafficSnapshot()
		if report != nil && len(report.Users) > 0 {
			if err := send(&pb.AgentUp{Msg: &pb.AgentUp_Traffic{Traffic: report}}); err != nil {
				return
			}
		}
		if ctx.Err() != nil {
			return
		}
		onTick()
	}
}
