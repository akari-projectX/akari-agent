package main

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseNetSockets(t *testing.T) {
	open := func(name string) *os.File {
		t.Helper()
		f, err := os.Open("testdata/proc/net/" + name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	tests := []struct {
		file string
		udp  bool
		want []netSocket
	}{
		// Only listeners: the established connections (state 01) on
		// port 22 and 54944 are not holders.
		{"tcp", false, []netSocket{{22, 0}, {20443, 64055}}},
		{"tcp6", false, []netSocket{{80, 33}, {20443, 64055}}},
		// UDP: every bound socket, connected or not.
		{"udp", true, []netSocket{{53, 101}, {60000, 64055}}},
	}
	for _, tc := range tests {
		got, err := parseNetSockets(open(tc.file), tc.udp)
		if err != nil {
			t.Fatalf("parseNetSockets(%s) error: %v", tc.file, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseNetSockets(%s) = %v, want %v", tc.file, got, tc.want)
		}
	}
}

func TestForeignHolder(t *testing.T) {
	socks := []netSocket{{22, 0}, {20443, 64055}, {20443, 64055}, {8080, 64055}, {8080, 1000}}
	tests := []struct {
		port    uint16
		wantUID uint32
		want    bool
	}{
		{22, 0, true},      // sshd (root) is not the agent's
		{20443, 0, false},  // the agent's own listener (a rebuild)
		{9999, 0, false},   // unbound: the agent binds it after asking
		{8080, 1000, true}, // shared with a foreign process
	}
	for _, tc := range tests {
		uid, got := foreignHolder(socks, tc.port, 64055)
		if got != tc.want || (got && uid != tc.wantUID) {
			t.Errorf("foreignHolder(port %d) = %d, %v; want %d, %v", tc.port, uid, got, tc.wantUID, tc.want)
		}
	}
}

func FuzzParseNetSockets(f *testing.F) {
	for _, n := range []string{"tcp", "tcp6", "udp"} {
		b, err := os.ReadFile("testdata/proc/net/" + n)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(string(b), n == "udp")
	}
	f.Add("0: :0016 x 0A 0 0 0 0\n", false)
	f.Fuzz(func(t *testing.T, s string, udp bool) {
		socks, _ := parseNetSockets(strings.NewReader(s), udp)
		// The holder check must not panic on any table.
		foreignHolder(socks, 22, 1)
	})
}
