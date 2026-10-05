package main

import (
	"context"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/core"

	"akari/agent/pb"
)

func newSessionID() string {
	return uuid.NewString()
}

// agentStats: the agent-side heartbeat values.
type agentStats struct {
	connections, onlineUsers, uptime uint64
}

// heartbeatLoop sends a Heartbeat every interval: CPU/memory, the gate's
// connection and user counts, uptime, the lease, and the machine status
// (W11, Heartbeat.metrics; smp keeps the previous readings for rates and
// belongs to this loop while it runs). cert: the automatic certificate
// (W10, Heartbeat.cert; nil = none); filter: the source allowlists (W28-a,
// Heartbeat.source_filter; nil = none).
func heartbeatLoop(ctx context.Context, every time.Duration, send func(*pb.AgentUp) error, lease func() (time.Duration, bool), stats func() agentStats, smp *sampler, cert func() *pb.CertStatus, filter func() *pb.SourceFilterStatus) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		hb := buildHeartbeat(smp, stats(), lease)
		if cert != nil {
			hb.Cert = cert()
		}
		if filter != nil {
			hb.SourceFilter = filter()
		}
		if err := send(&pb.AgentUp{Msg: &pb.AgentUp_Heartbeat{Heartbeat: hb}}); err != nil {
			return
		}
	}
}

func buildHeartbeat(smp *sampler, st agentStats, lease func() (time.Duration, bool)) *pb.Heartbeat {
	cpuPct, mem, m := smp.sample()
	m.OnlineUsers = uint32(min(st.onlineUsers, math.MaxUint32))
	m.XrayVersion = core.Version()
	hb := &pb.Heartbeat{
		CpuPercent:    cpuPct,
		Connections:   st.connections,
		UptimeSeconds: st.uptime,
		Metrics:       m,
	}
	if mem.hasMem {
		hb.MemUsedBytes, hb.MemTotalBytes = &mem.used, &mem.total
	}
	if left, armed := lease(); armed {
		secs := uint64(left / time.Second)
		hb.LeaseRemainingSeconds = &secs
	}
	return hb
}

// trafficLoop reports the cumulative counters that changed every interval
// (TrafficChanges; the stream's first report is complete, see ResetSent);
// onTick runs after each tick on which the stream was still usable.
func trafficLoop(ctx context.Context, every time.Duration, cm *CoreManager, send func(*pb.AgentUp) error, onTick func()) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if report := cm.TrafficChanges(); report != nil {
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
