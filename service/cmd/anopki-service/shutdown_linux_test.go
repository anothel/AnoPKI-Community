// SPDX-License-Identifier: MPL-2.0
package main

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/corecli"
)

func TestRunServerUntilShutdownSIGTERM(t *testing.T) {
	const helper = "ANOPKI_TEST_SIGTERM_HELPER"
	if os.Getenv(helper) != "1" {
		// Use a separate test process so SIGTERM cannot affect the Go test runner.
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunServerUntilShutdownSIGTERM$")
		cmd.Env = append(os.Environ(), helper+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("SIGTERM helper: %v\n%s", err, output)
		}
		return
	}

	root, stop := signal.NotifyContext(t.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveStarted := make(chan struct{})
	shutdownStarted := make(chan context.Context, 1)
	release := make(chan struct{})
	serveDone := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- runServerUntilShutdown(root, func() error {
			close(serveStarted)
			<-serveDone
			return http.ErrServerClosed
		}, func(ctx context.Context) error {
			defer close(serveDone)
			shutdownStarted <- ctx
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}, 5*time.Second, nil)
	}()

	select {
	case <-serveStarted:
	case err := <-result:
		t.Fatalf("server returned before starting: %v", err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM to test helper: %v", err)
	}
	select {
	case shutdown := <-shutdownStarted:
		if !errors.Is(root.Err(), context.Canceled) {
			t.Errorf("root context after SIGTERM = %v, want canceled", root.Err())
		}
		if _, ok := shutdown.Deadline(); !ok || shutdown.Err() != nil {
			t.Errorf("shutdown context has deadline = %t, error = %v, want a fresh bounded context", ok, shutdown.Err())
		}
	case err := <-result:
		t.Fatalf("server returned before graceful shutdown: %v", err)
	}

	close(release)
	if err := <-result; err != nil {
		t.Fatalf("graceful shutdown after SIGTERM: %v", err)
	}
}

func TestCoreCLICancellationKillsWaitsAndReaps(t *testing.T) {
	dir := t.TempDir()
	csrDir := t.TempDir()
	t.Setenv("TMPDIR", csrDir)
	ready := openShutdownFIFO(t, filepath.Join(dir, "ready"))
	hold := openShutdownFIFO(t, filepath.Join(dir, "hold"))
	t.Setenv("ANOPKI_TEST_CORE_READY", ready.Name())
	t.Setenv("ANOPKI_TEST_CORE_HOLD", hold.Name())

	// Only shell builtins are used, so the process announcing its PID has no children.
	bin := filepath.Join(dir, "fake-core")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' '{\"code\":\"test_cancel\",\"message\":\"fixture ready\"}' >&2\n" +
		"printf '%s\\n' \"$$\" > \"$ANOPKI_TEST_CORE_READY\"\n" +
		"IFS= read -r ignored < \"$ANOPKI_TEST_CORE_HOLD\"\n"
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := ready.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	var runErr error
	go func() {
		defer close(done)
		_, runErr = (corecli.Runner{Bin: bin}).InspectCSR(ctx, "test CSR fixture")
	}()
	defer func() {
		cancel()
		// On failure, also release the fake CLI's read so the runner can reap it.
		hold.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("core CLI runner did not finish during cleanup")
		}
	}()

	line, err := bufio.NewReader(ready).ReadString('\n')
	if err != nil {
		t.Fatalf("wait for fake core CLI readiness: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || pid <= 0 {
		t.Fatalf("invalid fake core CLI PID %q", line)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("core CLI runner did not return after cancellation")
	}

	var commandErr *corecli.CommandError
	var exitErr *exec.ExitError
	if !errors.As(runErr, &commandErr) || commandErr.Code != "test_cancel" ||
		commandErr.Message != "fixture ready" || !errors.As(runErr, &exitErr) {
		t.Fatalf("runner error = %v, want structured fixture error wrapping the child exit", runErr)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if exitErr.Pid() != pid || !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("child exit = PID %d, status %v, want PID %d killed by SIGKILL", exitErr.Pid(), exitErr.Sys(), pid)
	}

	var reapedStatus syscall.WaitStatus
	if got, err := syscall.Wait4(pid, &reapedStatus, syscall.WNOHANG, nil); !errors.Is(err, syscall.ECHILD) {
		t.Fatalf("wait4(%d) = (%d, %v), want ECHILD after the runner reaped its child", pid, got, err)
	}
	if entries, err := os.ReadDir(csrDir); err != nil || len(entries) != 0 {
		t.Fatalf("temporary CSR directory = (%v, %v), want empty", entries, err)
	}
}

func openShutdownFIFO(t *testing.T, path string) *os.File {
	t.Helper()
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatalf("create test FIFO: %v", err)
	}
	// Opening both ends keeps each fixture barrier available until cleanup.
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0600)
	if err != nil {
		t.Fatalf("open test FIFO: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
