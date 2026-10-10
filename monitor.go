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
// belongs to this loop while it runs). fill adds the rest (W10
// Heartbeat.cert, W29 Heartbeat.block, W28-a Heartbeat.source_filter;
// nil = nothing).
func heartbeatLoop(ctx context.Context, every time.Duration, send func(*pb.AgentUp) error, lease func() (time.Duration, bool), stats func() agentStats, smp *sampler, fill func(*pb.Heartbeat)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		hb := buildHeartbeat(smp, stats(), lease)
		if fill != nil {
			fill(hb)
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
			if err := sendTraffic(send, report); err != nil {
				return
			}
		}
		if ctx.Err() != nil {
			return
		}
		onTick()
	}
}

// maxReportRows bounds the rows of one TrafficReport message. The panel
// drops a report with more than 65,536 rows whole (traffic.rs
// MAX_REPORT_ROWS) and counts every row on its own (cumulative per key and
// session), so a large counter set is sent as several reports of the same
// session: 20k users on 4 entrances is 80k rows.
const maxReportRows = 16384

// trafficChunks splits r into reports of at most maxReportRows rows each
// (r itself when it already fits; never an empty slice for a non-nil r).
func trafficChunks(r *pb.TrafficReport) []*pb.TrafficReport {
	if len(r.Users) <= maxReportRows {
		return []*pb.TrafficReport{r}
	}
	out := make([]*pb.TrafficReport, 0, (len(r.Users)+maxReportRows-1)/maxReportRows)
	for i := 0; i < len(r.Users); i += maxReportRows {
		end := min(i+maxReportRows, len(r.Users))
		out = append(out, &pb.TrafficReport{Users: r.Users[i:end:end], MonotonicMs: r.MonotonicMs, SessionId: r.SessionId})
	}
	return out
}

// sendTraffic sends r in chunks of at most maxReportRows rows; the first
// error stops it (the stream is then dead and the next one resends).
func sendTraffic(send func(*pb.AgentUp) error, r *pb.TrafficReport) error {
	for _, c := range trafficChunks(r) {
		if err := send(&pb.AgentUp{Msg: &pb.AgentUp_Traffic{Traffic: c}}); err != nil {
			return err
		}
	}
	return nil
}
