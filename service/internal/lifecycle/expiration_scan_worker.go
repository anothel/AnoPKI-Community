// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"context"
	"time"
)

const expirationScanWorkerActor = "system:expiration-scan-worker"

type ExpirationScanner interface {
	ScanCertificateExpirations(context.Context, string, ScanCertificateExpirationsRequest) (CertificateExpirationScanResult, error)
}

type ExpirationScanWorker struct {
	scanner       ExpirationScanner
	interval      time.Duration
	warningWindow time.Duration
	batchSize     int
	logf          func(string, ...any)
}

func NewExpirationScanWorker(scanner ExpirationScanner, interval time.Duration, warningWindow time.Duration, batchSize int, logf func(string, ...any)) *ExpirationScanWorker {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &ExpirationScanWorker{
		scanner:       scanner,
		interval:      interval,
		warningWindow: warningWindow,
		batchSize:     batchSize,
		logf:          logf,
	}
}

func (w *ExpirationScanWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	w.runWithTicks(ctx, ticker.C)
}

func (w *ExpirationScanWorker) runWithTicks(ctx context.Context, ticks <-chan time.Time) {
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

func (w *ExpirationScanWorker) runOnce(ctx context.Context) {
	result, err := w.scanner.ScanCertificateExpirations(ctx, expirationScanWorkerActor, ScanCertificateExpirationsRequest{
		WarningWindow: w.warningWindow,
		Limit:         w.batchSize,
	})
	if err != nil {
		w.logf("expiration scan worker: %v", err)
		return
	}
	w.logf("expiration scan worker: expired=%d expiration_warnings=%d", len(result.Expired), len(result.ExpirationWarnings))
}
