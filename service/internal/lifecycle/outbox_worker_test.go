// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
	"github.com/anothel/anopki/service/internal/store"
	_ "modernc.org/sqlite"
)

func TestOutboxWorkerRunsImmediatelyAndOnTicks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runner := &recordingOutboxRunner{callCh: make(chan int, 4)}
	logs := make([]string, 0)
	worker := NewOutboxWorker(runner, time.Hour, 7, func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	})
	ticks := make(chan time.Time)
	errStop := errors.New("storage down")

	done := make(chan struct{})
	go func() {
		worker.runWithTicks(ctx, ticks)
		close(done)
	}()

	waitForCall(t, runner.callCh, 7)
	ticks <- time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	waitForCall(t, runner.callCh, 7)
	runner.setErr(errStop)
	ticks <- time.Date(2026, time.January, 2, 3, 4, 6, 0, time.UTC)
	waitForCall(t, runner.callCh, 7)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after context cancel")
	}
	if len(logs) != 1 || logs[0] != "outbox worker: storage down" {
		t.Fatalf("logs = %#v, want storage error", logs)
	}
}

type recordingOutboxRunner struct {
	mu     sync.Mutex
	err    error
	callCh chan int
}

func (r *recordingOutboxRunner) RunOnce(ctx context.Context, limit int) (int, error) {
	r.mu.Lock()
	err := r.err
	r.mu.Unlock()
	r.callCh <- limit
	return 0, err
}

func (r *recordingOutboxRunner) setErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

func waitForCall(t *testing.T, calls <-chan int, wantLimit int) {
	t.Helper()

	select {
	case got := <-calls:
		if got != wantLimit {
			t.Fatalf("RunOnce limit = %d, want %d", got, wantLimit)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for RunOnce")
	}
}

func TestOutboxWorkerDrainsCanceledDeliveryAndRecoversLease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "worker.sqlite")
		db, repo := openWorkerDrainStore(t, path)
		if err := store.ApplyInitialMigration(t.Context(), db, "sqlite"); err != nil {
			t.Fatal(err)
		}
		ctx := t.Context()
		clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
		message := domain.OutboxMessage{
			ID: "shutdown-outbox", Type: "certificate.expired", PayloadJSON: "{}",
			Status: domain.OutboxPending, AvailableAt: clock.now,
			CreatedAt: clock.now, UpdatedAt: clock.now,
		}
		if err := repo.CreateOutboxMessage(ctx, message); err != nil {
			t.Fatal(err)
		}

		barrier := newWorkerDrainBarrier(db)
		var canceledDeliveries int
		dispatcher := NewOutboxDispatcher(repo, OutboxHandlerFunc(func(ctx context.Context, _ domain.OutboxMessage) error {
			canceledDeliveries++
			return barrier.wait(ctx)
		}), clock, &fakeIDGenerator{})
		var logs []string
		worker := NewOutboxWorker(dispatcher, time.Hour, 1, func(format string, args ...any) {
			logs = append(logs, fmt.Sprintf(format, args...))
		})
		checkWorkerDrain(t, barrier, func(ctx context.Context) { worker.runWithTicks(ctx, nil) })
		if canceledDeliveries != 1 || len(logs) != 1 || logs[0] != "outbox worker: context canceled" {
			t.Fatalf("deliveries = %d, logs = %v, want one canceled delivery", canceledDeliveries, logs)
		}

		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		_, repo = openWorkerDrainStore(t, path)

		leased, err := repo.GetOutboxMessage(ctx, message.ID)
		if err != nil || leased.Status != domain.OutboxProcessing || !leased.ProcessingDeadlineAt.After(clock.now) {
			t.Fatalf("outbox after cancellation = (%+v, %v), want a retained processing lease", leased, err)
		}
		attempts, err := repo.ListJobAttemptsByOutboxMessage(ctx, message.ID)
		if err != nil || len(attempts) != 0 {
			t.Fatalf("attempts after cancellation = (%v, %v), want none", attempts, err)
		}

		var recoveredDeliveries int
		handler := OutboxHandlerFunc(func(_ context.Context, got domain.OutboxMessage) error {
			if got.ID != message.ID {
				return fmt.Errorf("delivery ID = %q, want %q", got.ID, message.ID)
			}
			recoveredDeliveries++
			return nil
		})
		beforeExpiry := NewOutboxDispatcher(repo, handler, clock, &fakeIDGenerator{})
		if processed, err := beforeExpiry.RunOnce(ctx, 1); err != nil || processed != 0 || recoveredDeliveries != 0 {
			t.Fatalf("recovery with active lease = (%d, %v), deliveries = %d", processed, err, recoveredDeliveries)
		}
		restarted := NewOutboxDispatcher(repo, handler, fixedClock{now: leased.ProcessingDeadlineAt}, &fakeIDGenerator{})
		if processed, err := restarted.RunOnce(ctx, 1); err != nil || processed != 1 {
			t.Fatalf("recovery after lease expiry = (%d, %v), want (1, nil)", processed, err)
		}
		if processed, err := restarted.RunOnce(ctx, 1); err != nil || processed != 0 || recoveredDeliveries != 1 {
			t.Fatalf("repeat dispatch = (%d, %v), deliveries = %d, want no duplicate", processed, err, recoveredDeliveries)
		}
		attempts, err = repo.ListJobAttemptsByOutboxMessage(ctx, message.ID)
		if err != nil || len(attempts) != 1 || attempts[0].Status != domain.JobAttemptSucceeded {
			t.Fatalf("attempts after recovery = (%v, %v), want one success", attempts, err)
		}
	})
}

func openWorkerDrainStore(t *testing.T, path string) (*sql.DB, *store.SQLStore) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close worker fixture database: %v", err)
		}
	})
	return db, store.NewSQLStore(db)
}

type workerDrainBarrier struct {
	db       *sql.DB
	entered  chan struct{}
	canceled chan struct{}
	release  chan struct{}
	dbProbe  error
}

func newWorkerDrainBarrier(db *sql.DB) *workerDrainBarrier {
	return &workerDrainBarrier{
		db: db, entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}),
	}
}

func (b *workerDrainBarrier) wait(ctx context.Context) error {
	close(b.entered)
	<-ctx.Done()
	close(b.canceled)
	<-b.release
	// This probe models cleanup that still needs the pool after cancellation.
	var value int
	b.dbProbe = b.db.QueryRowContext(context.WithoutCancel(ctx), "SELECT 1").Scan(&value)
	return ctx.Err()
}

func checkWorkerDrain(t *testing.T, barrier *workerDrainBarrier, run func(context.Context)) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	release := sync.OnceFunc(func() { close(barrier.release) })
	defer release()

	done := make(chan struct{})
	go func() {
		defer close(done)
		run(ctx)
	}()
	synctest.Wait()
	select {
	case <-barrier.entered:
	default:
		t.Fatal("worker never entered the operation")
	}
	cancel()
	synctest.Wait()
	select {
	case <-barrier.canceled:
	default:
		t.Fatal("in-flight operation did not receive cancellation")
	}
	select {
	case <-done:
		t.Fatal("worker returned with its operation still blocked")
	default:
	}

	release()
	synctest.Wait()
	select {
	case <-done:
	default:
		t.Fatal("worker did not return after the operation completed")
	}
	if barrier.dbProbe != nil {
		t.Fatalf("database unavailable during in-flight cleanup: %v", barrier.dbProbe)
	}
}
