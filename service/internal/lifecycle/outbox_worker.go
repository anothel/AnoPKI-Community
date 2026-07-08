// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"context"
	"time"
)

type OutboxRunner interface {
	RunOnce(context.Context, int) (int, error)
}

type OutboxWorker struct {
	runner   OutboxRunner
	interval time.Duration
	batch    int
	logf     func(string, ...any)
}

func NewOutboxWorker(runner OutboxRunner, interval time.Duration, batch int, logf func(string, ...any)) *OutboxWorker {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &OutboxWorker{
		runner:   runner,
		interval: interval,
		batch:    batch,
		logf:     logf,
	}
}

func (w *OutboxWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	w.runWithTicks(ctx, ticker.C)
}

func (w *OutboxWorker) runWithTicks(ctx context.Context, ticks <-chan time.Time) {
	w.runOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			w.runOnce(ctx)
		}
	}
}

func (w *OutboxWorker) runOnce(ctx context.Context) {
	if _, err := w.runner.RunOnce(ctx, w.batch); err != nil {
		w.logf("outbox worker: %v", err)
	}
}
