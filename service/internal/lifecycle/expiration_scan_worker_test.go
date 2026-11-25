// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
	"github.com/anothel/anopki/service/internal/store"
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

func TestExpirationScanWorkerDrainsCanceledScanAndRestartsOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "worker.sqlite")
		db, repo := openWorkerDrainStore(t, path)
		if err := store.ApplyInitialMigration(t.Context(), db, "sqlite"); err != nil {
			t.Fatal(err)
		}
		ctx := t.Context()
		clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
		cert := expirationLifecycleCertificate("shutdown-expiration", domain.CertificateValid, clock.now.Add(-time.Hour), time.Time{})
		if err := repo.CreateCertificate(ctx, cert); err != nil {
			t.Fatal(err)
		}

		barrier := newWorkerDrainBarrier(db)
		scanner := New(&gatedExpirationRepository{Repository: repo, wait: barrier.wait}, &fakeIssuer{}, clock, &fakeIDGenerator{})
		var logs []string
		worker := NewExpirationScanWorker(scanner, time.Hour, 24*time.Hour, 1, func(format string, args ...any) {
			logs = append(logs, fmt.Sprintf(format, args...))
		})
		checkWorkerDrain(t, barrier, func(ctx context.Context) { worker.runWithTicks(ctx, nil) })
		if len(logs) != 1 || logs[0] != "expiration scan worker: context canceled" {
			t.Fatalf("logs = %v, want one canceled scan", logs)
		}

		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		_, repo = openWorkerDrainStore(t, path)

		stored, err := repo.GetCertificate(ctx, cert.ID)
		if err != nil || stored.Status != domain.CertificateValid {
			t.Fatalf("certificate after cancellation = (%+v, %v), want valid", stored, err)
		}
		restarted := New(repo, &fakeIssuer{}, clock, &fakeIDGenerator{})
		if events, err := restarted.ListAuditEvents(ctx); err != nil || len(events) != 0 {
			t.Fatalf("audit events after cancellation = (%v, %v), want none", events, err)
		}
		if messages, err := repo.ListDueOutboxMessages(ctx, clock.now, 10); err != nil || len(messages) != 0 {
			t.Fatalf("outbox after cancellation = (%v, %v), want no messages", messages, err)
		}

		req := ScanCertificateExpirationsRequest{WarningWindow: 24 * time.Hour, Limit: 1}
		result, err := restarted.ScanCertificateExpirations(ctx, expirationScanWorkerActor, req)
		if err != nil || len(result.Expired) != 1 || result.Expired[0].ID != cert.ID {
			t.Fatalf("restarted scan = (%+v, %v), want one expiration", result, err)
		}
		result, err = restarted.ScanCertificateExpirations(ctx, expirationScanWorkerActor, req)
		if err != nil || len(result.Expired) != 0 || len(result.ExpirationWarnings) != 0 {
			t.Fatalf("repeat scan = (%+v, %v), want no changes", result, err)
		}
		events, err := restarted.ListAuditEvents(ctx)
		if err != nil || len(events) != 1 || events[0].Action != "certificate.expired" {
			t.Fatalf("audit events = (%v, %v), want one expiration", events, err)
		}
		messages, err := repo.ListDueOutboxMessages(ctx, clock.now, 10)
		if err != nil || len(messages) != 1 || messages[0].Type != "certificate.expired" {
			t.Fatalf("outbox = (%v, %v), want one expiration message", messages, err)
		}
	})
}

type gatedExpirationRepository struct {
	store.Repository
	wait func(context.Context) error
}

func (r *gatedExpirationRepository) WithinTx(ctx context.Context, fn func(store.Repository) error) error {
	return r.Repository.WithinTx(ctx, func(tx store.Repository) error {
		if err := fn(tx); err != nil {
			return err
		}
		// Park the scan after the transaction has staged its side effects.
		return r.wait(ctx)
	})
}
