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
