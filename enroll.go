package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"akari/agent/pb"
)

// Enrollment and certificate renewal (M1-8).
//
// Enrollment: the key is generated and persisted (0600) BEFORE the panel
// is asked, so a retry uses the same key; the token is single use on the
// panel. Re-enrollment happens when the bootstrap file carries a token
// other than the one this state directory last enrolled with (the admin
// issued a new one: lost state, expired certificate).
//
// Renewal (protocol 2): once less than a third of the current
// certificate's lifetime is left, a NEW key and CSR go to the panel over the
// live mTLS connection (AgentChannel.Renew). The answer is stored as
// identity.next.pem; the current identity stays on disk and in use. The
// stream is then restarted with the renewed identity, which is promoted to
// identity.pem only when the panel sent something on that stream (it
// accepted the certificate). Until then the panel keeps accepting the old
// certificate, so a crash anywhere in between costs nothing: the agent
// renews again or retries the pending one.

const enrolledMarker = "enrolled.token.sha256"

func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ensureEnrolled enrolls when the node has no identity yet, or when the
// bootstrap file carries a new token. Returns an error only for a
// permanent failure (no token, token refused, CSR refused); transient
// failures are retried while ctx lives.
func (a *Agent) ensureEnrolled(ctx context.Context) error {
	token := strings.TrimSpace(a.cfg.EnrollmentToken)
	cur := a.ids.current()
	marker, _ := os.ReadFile(filepath.Join(a.ids.dir, enrolledMarker))
	fresh := token != "" && strings.TrimSpace(string(marker)) != tokenDigest(token)
	switch {
	case cur == nil && token == "":
		return errors.New("no identity: the bootstrap file has neither an enrollment_token nor a v1 key")
	case cur != nil && !fresh:
		return nil
	}
	backoff := a.backoffBase
	for {
		err := a.enrollOnce(ctx, token)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		// The panel accepted the request (its one-time token is spent) but
		// this machine cannot keep the result: retrying can only fail with
		// "token used" and hide the real cause.
		var se *storeError
		if errors.As(err, &se) {
			if cur != nil {
				slog.Error("enrollment succeeded on the panel but the identity could not be stored; "+
					"keeping the current identity (issue a new token after fixing the cause)", "error", se.err)
				a.recordEnrolledToken(token)
				return nil
			}
			return fmt.Errorf("enrollment succeeded on the panel but the identity cannot be stored "+
				"(the token is spent; fix the cause, then issue a new one): %w", se.err)
		}
		switch status.Code(err) {
		case codes.PermissionDenied:
			msg := "enrollment refused: the token is unknown, used or expired; issue a new one " +
				"(akari node enroll-token <node id>) and put it in the bootstrap file"
			if cur != nil {
				// Keep running with what we have, and do not ask again with
				// this token on every restart (G5).
				slog.Error(msg)
				a.recordEnrolledToken(token)
				return nil
			}
			return errors.New(msg)
		case codes.InvalidArgument:
			return fmt.Errorf("enrollment: the panel refused the request: %w", err)
		}
		wait := fullJitter(backoff)
		slog.Warn("enrollment failed, retrying", "error", err, "retry_in", wait)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		backoff = min(backoff*2, 30*a.backoffBase)
	}
}

func (a *Agent) enrollOnce(ctx context.Context, token string) error {
	key, err := a.ids.enrollKey()
	if err != nil {
		return fmt.Errorf("enrollment key: %w", err)
	}
	csr, err := csrFor(key)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := a.enrollRPC(cctx, &pb.EnrollRequest{Token: token, CsrDer: csr})
	if err != nil {
		return err
	}
	if err := a.ids.storeEnrolled(key, []byte(resp.GetCertPem())); err != nil {
		return &storeError{err}
	}
	a.recordEnrolledToken(token)
	cur := a.ids.current()
	slog.Info("enrolled", "cert_not_after", cur.leaf.NotAfter, "serial", cur.leaf.SerialNumber.Text(16))
	return nil
}

// storeError: the enrollment RPC succeeded but the result could not be
// stored locally (a permanent, local failure: the token is already spent).
type storeError struct{ err error }

func (e *storeError) Error() string { return "store enrolled identity: " + e.err.Error() }
func (e *storeError) Unwrap() error { return e.err }

// recordEnrolledToken remembers which bootstrap token this state directory
// has dealt with (enrolled, or been refused for), so a restart does not ask
// the panel again.
func (a *Agent) recordEnrolledToken(token string) {
	if err := writeSecret(filepath.Join(a.ids.dir, enrolledMarker), []byte(tokenDigest(token)+"\n")); err != nil {
		slog.Warn("failed to record the enrollment token digest", "error", err)
	}
}

// enrollPanel calls AgentEnrollment.Enroll without a client certificate.
func (a *Agent) enrollPanel(ctx context.Context, req *pb.EnrollRequest) (*pb.IssuedCertificate, error) {
	conn, err := a.clientConn(nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return pb.NewAgentEnrollmentClient(conn).Enroll(ctx, req)
}

// renewLoop checks the current certificate periodically (at most every
// renewCheckEvery, and at least 20 times per lifetime for short test
// validities).
func (a *Agent) renewLoop(ctx context.Context) {
	for {
		wait := a.renewCheckEvery
		if cur := a.ids.current(); cur != nil {
			if l := cur.leaf.NotAfter.Sub(cur.leaf.NotBefore) / 20; l < wait {
				wait = l
			}
		}
		wait = max(wait, 50*time.Millisecond)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		a.renewTick(ctx)
	}
}

func (a *Agent) renewTick(ctx context.Context) {
	if next := a.ids.pending(); next != nil {
		// Waiting for the renewed certificate's first successful stream.
		a.streamMu.Lock()
		stale := a.curCancel != nil && !a.curViaNext && a.now().Sub(a.curStart) > a.nextRetryAfter
		cancel := a.curCancel
		a.streamMu.Unlock()
		if stale {
			slog.Info("retrying the renewed certificate")
			cancel()
		}
		return
	}
	cur := a.ids.current()
	if cur == nil {
		return
	}
	now := a.now()
	a.renewMu.Lock()
	retryAt := a.renewRetryAt
	a.renewMu.Unlock()
	if now.Before(renewAt(cur.leaf)) || now.Before(retryAt) {
		return
	}
	a.streamMu.Lock()
	conn, cancel := a.curConn, a.curCancel
	a.streamMu.Unlock()
	if conn == nil {
		return // renew over a live, accepted stream only
	}
	if err := a.renewOnce(ctx, conn); err != nil {
		backoff := a.renewFailed()
		if status.Code(err) == codes.Unimplemented {
			backoff = time.Hour // the panel predates renewal
			a.renewMu.Lock()
			a.renewRetryAt = now.Add(backoff)
			a.renewMu.Unlock()
		}
		slog.Warn("certificate renewal failed", "error", err, "retry_in", backoff,
			"cert_not_after", cur.leaf.NotAfter)
		return
	}
	a.renewMu.Lock()
	a.renewFailures = 0
	a.renewMu.Unlock()
	slog.Info("certificate renewed; reconnecting with it")
	cancel()
}

// renewFailed backs renewal off: 10 s doubling to 10 min.
func (a *Agent) renewFailed() time.Duration {
	a.renewMu.Lock()
	defer a.renewMu.Unlock()
	a.renewFailures++
	backoff := min(10*time.Second<<min(a.renewFailures-1, 6), 10*time.Minute)
	a.renewRetryAt = a.now().Add(backoff)
	return backoff
}

func (a *Agent) renewOnce(ctx context.Context, conn grpc.ClientConnInterface) error {
	key, err := newKey()
	if err != nil {
		return err
	}
	csr, err := csrFor(key)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := pb.NewAgentChannelClient(conn).Renew(cctx, &pb.RenewRequest{CsrDer: csr})
	if err != nil {
		return err
	}
	if err := a.ids.storeNext(key, []byte(resp.GetCertPem())); err != nil {
		return fmt.Errorf("store renewed identity: %w", err)
	}
	return nil
}

// refusedCert: the stream ended because the panel does not accept the
// certificate (as opposed to a network problem).
func refusedCert(err error) bool {
	if err == nil {
		return false
	}
	if status.Code(err) == codes.Unauthenticated {
		return true
	}
	return strings.Contains(err.Error(), "remote error: tls:")
}
