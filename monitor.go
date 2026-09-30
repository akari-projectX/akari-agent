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

func heartbeatLoop(ctx context.Context, send func(*pb.AgentUp) error) {
	ticker := time.NewTicker(15 * time.Second)
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
		if err := send(&pb.AgentUp{Msg: &pb.AgentUp_Heartbeat{Heartbeat: hb}}); err != nil {
			return
		}
	}
}

func trafficLoop(ctx context.Context, cm *CoreManager, send func(*pb.AgentUp) error) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		users := cm.TrafficSnapshot()
		if len(users) == 0 {
			continue
		}
		report := &pb.TrafficReport{Users: users}
		if err := send(&pb.AgentUp{Msg: &pb.AgentUp_Traffic{Traffic: report}}); err != nil {
			return
		}
	}
}
