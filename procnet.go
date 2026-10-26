package main

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// Sockets from /proc/net/{tcp,tcp6,udp,udp6}, for the root updater's
// decision which ports an agent-requested source filter may touch
// (sourcefilter_root_linux.go, audit 2026-10 P2-1).

// netSocket is one bound socket of a /proc/net table: the local port and
// the uid of the socket's owner.
type netSocket struct {
	port uint16
	uid  uint32
}

// tcpListen is the state column value of a listening TCP socket.
const tcpListen = "0A"

// parseNetSockets reads a /proc/net/{tcp,tcp6,udp,udp6} table and returns
// the bound sockets: listening ones for TCP (state 0A), every one for UDP
// (a bound, unconnected UDP socket is state 07, a connected one 01; both
// hold the port). Unparsable lines are skipped; the header line never
// parses. The reader is consumed line by line (the tables can be large).
func parseNetSockets(r io.Reader, udp bool) ([]netSocket, error) {
	var out []netSocket
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		// sl local_address rem_address st tx:rx tr:tm->when retrnsmt uid ...
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			continue
		}
		if !udp && f[3] != tcpListen {
			continue
		}
		i := strings.LastIndexByte(f[1], ':')
		if i < 0 {
			continue
		}
		port, err := strconv.ParseUint(f[1][i+1:], 16, 16)
		if err != nil {
			continue
		}
		uid, err := strconv.ParseUint(f[7], 10, 32)
		if err != nil {
			continue
		}
		out = append(out, netSocket{port: uint16(port), uid: uint32(uid)})
	}
	return out, sc.Err()
}

// foreignHolder reports whether a socket in socks that is bound to port
// belongs to another user than uid, and that user.
func foreignHolder(socks []netSocket, port uint16, uid uint32) (uint32, bool) {
	for _, s := range socks {
		if s.port == port && s.uid != uid {
			return s.uid, true
		}
	}
	return 0, false
}
