package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"akari/agent/pb"
)

// echoServer accepts connections and echoes every byte back.
func echoServer(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// vlessConn is a minimal raw VLESS (no flow) client over plain TCP.
type vlessConn struct {
	net.Conn
	r         *bufio.Reader
	gotHeader bool
}

func vlessDial(inboundPort int, id string, destPort int) (*vlessConn, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", inboundPort), 2*time.Second)
	if err != nil {
		return nil, err
	}
	u, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}
	hdr := []byte{0}           // version
	hdr = append(hdr, u[:]...) // user id
	hdr = append(hdr, 0, 1)    // no addons, command TCP
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(destPort))
	hdr = append(hdr, 1, 127, 0, 0, 1) // IPv4 127.0.0.1
	if _, err := c.Write(hdr); err != nil {
		c.Close()
		return nil, err
	}
	return &vlessConn{Conn: c, r: bufio.NewReader(c)}, nil
}

// echo sends msg through the proxy and expects it back.
func (v *vlessConn) echo(msg string) error {
	_ = v.SetDeadline(time.Now().Add(3 * time.Second))
	defer v.SetDeadline(time.Time{})
	if _, err := v.Write([]byte(msg)); err != nil {
		return err
	}
	if !v.gotHeader {
		var h [2]byte
		if _, err := io.ReadFull(v.r, h[:]); err != nil {
			return fmt.Errorf("response header: %w", err)
		}
		if h[1] > 0 {
			if _, err := v.r.Discard(int(h[1])); err != nil {
				return err
			}
		}
		v.gotHeader = true
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(v.r, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return fmt.Errorf("echo mismatch: %q", buf)
	}
	return nil
}

// closedWithin reports whether the proxy closes the connection in time.
func (v *vlessConn) closedWithin(d time.Duration) bool {
	_ = v.SetReadDeadline(time.Now().Add(d))
	_, err := v.r.ReadByte()
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return err != nil
}

const (
	userA = "aaaaaaaa-0000-0000-0000-00000000000a"
	userB = "bbbbbbbb-0000-0000-0000-00000000000b"
	idA   = "0a0a0a0a-1111-4111-8111-111111111111"
	idB   = "0b0b0b0b-2222-4222-8222-222222222222"
	idB2  = "0b0b0b0b-3333-4333-8333-333333333333"
)

func vlessUser(user, tag, id string) *pb.UserOp {
	return &pb.UserOp{Op: pb.UserOp_ADD, UserId: user, InboundUsers: []*pb.InboundUser{{
		InboundTag: tag, Protocol: "vless", AccountJson: fmt.Sprintf(`{"flow":"","id":%q}`, id)}}}
}

func twoInbounds(p1, p2 int) string {
	return fmt.Sprintf(`[{"tag":"in-a","listen":"127.0.0.1","port":%d,"protocol":"vless",`+
		`"settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp"}},`+
		`{"tag":"in-b","listen":"127.0.0.1","port":%d,"protocol":"vless",`+
		`"settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp"}}]`, p1, p2)
}

// selfSigned: a P-256 certificate for "rt.test" (PEM and parsed).
func selfSigned(t *testing.T) (certPEM, keyPEM string, c tls.Certificate) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rt.test"}, DNSNames: []string{"rt.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	c, err = tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	return
}
