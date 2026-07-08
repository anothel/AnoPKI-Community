// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestExpirationScanWorkerRunsImmediatelyAndOnTicks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scanner := &recordingExpirationScanner{callCh: make(chan expirationScanCall, 4)}
	logs := make([]string, 0)
	worker := NewExpirationScanWorker(scanner, time.Hour, 30*24*time.Hour, 11, func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	})
	ticks := make(chan time.Time)
	errStop := errors.New("storage down")

	done := make(chan struct{})
	go func() {
		worker.runWithTicks(ctx, ticks)
		close(done)
	}()

	waitForExpirationScan(t, scanner.callCh, 30*24*time.Hour, 11)
	ticks <- time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	waitForExpirationScan(t, scanner.callCh, 30*24*time.Hour, 11)
	scanner.setResult(CertificateExpirationScanResult{}, errStop)
	ticks <- time.Date(2026, time.January, 2, 3, 4, 6, 0, time.UTC)
	waitForExpirationScan(t, scanner.callCh, 30*24*time.Hour, 11)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after context cancel")
	}
	if len(logs) != 3 {
		t.Fatalf("logs = %#v, want three scan log entries", logs)
	}
	if logs[0] != "expiration scan worker: expired=0 expiration_warnings=0" {
		t.Fatalf("first log = %q", logs[0])
	}
	if logs[2] != "expiration scan worker: storage down" {
		t.Fatalf("error log = %q", logs[2])
	}
}

type expirationScanCall struct {
	actor string
	req   ScanCertificateExpirationsRequest
}

type recordingExpirationScanner struct {
	mu     sync.Mutex
	result CertificateExpirationScanResult
	err    error
	callCh chan expirationScanCall
}

func (r *recordingExpirationScanner) ScanCertificateExpirations(ctx context.Context, actor string, req ScanCertificateExpirationsRequest) (CertificateExpirationScanResult, error) {
	r.mu.Lock()
	result := r.result
	err := r.err
	r.mu.Unlock()
	r.callCh <- expirationScanCall{actor: actor, req: req}
	return result, err
}

func (r *recordingExpirationScanner) setResult(result CertificateExpirationScanResult, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.result = result
	r.err = err
}

func waitForExpirationScan(t *testing.T, calls <-chan expirationScanCall, wantWindow time.Duration, wantLimit int) {
	t.Helper()

	select {
	case got := <-calls:
		if got.actor != "system:expiration-scan-worker" {
			t.Fatalf("actor = %q, want system worker actor", got.actor)
		}
		if got.req.WarningWindow != wantWindow || got.req.Limit != wantLimit {
			t.Fatalf("request = %#v, want window %s limit %d", got.req, wantWindow, wantLimit)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for expiration scan")
	}
}
