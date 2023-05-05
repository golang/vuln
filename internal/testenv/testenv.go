// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testenv

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

var origEnv = os.Environ()

// NeedsExec checks that the current system can start new processes
// using os.StartProcess or (more commonly) exec.Command.
// If not, NeedsExec calls t.Skip with an explanation.
//
// On some platforms NeedsExec checks for exec support by re-executing the
// current executable, which must be a binary built by 'go test'.
// We intentionally do not provide a HasExec function because of the risk of
// inappropriate recursion in TestMain functions.
func NeedsExec(t testing.TB) {
	tryExecOnce.Do(func() {
		tryExecErr = tryExec()
	})
	if tryExecErr != nil {
		t.Helper()
		t.Skipf("skipping test: cannot exec subprocess on %s/%s: %v", runtime.GOOS, runtime.GOARCH, tryExecErr)
	}
}

var (
	tryExecOnce sync.Once
	tryExecErr  error
)

func tryExec() error {
	switch runtime.GOOS {
	case "aix",
		"android",
		"darwin",
		"dragonfly",
		"freebsd",
		"illumos",
		"linux",
		"netbsd",
		"openbsd",
		"plan9",
		"solaris",
		"windows":
		// Known OS that isn't ios or wasm; assume that exec works.
		return nil
	default:
	}

	// ios has an exec syscall but on real iOS devices it might return a
	// permission error. In an emulated environment (such as a Corellium host)
	// it might succeed, so if we need to exec we'll just have to try it and
	// find out.
	//
	// As of 2023-04-19 wasip1 and js don't have exec syscalls at all, but we
	// may as well use the same path so that this branch can be tested without
	// an ios environment.

	if flag.Lookup("test.list") == nil {
		// This isn't a standard 'go test' binary, so we don't know how to
		// self-exec in a way that should succeed without side effects.
		// Just forget it.
		return errors.New("can't probe for exec support with a non-test executable")
	}

	// We know that this is a test executable. We should be able to run it with a
	// no-op flag to check for overall exec support.
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("can't probe for exec support: %w", err)
	}
	cmd := exec.Command(exe, "-test.list=^$")
	cmd.Env = origEnv
	return cmd.Run()
}

func NeedsGoBuild(t testing.TB) {
	goBuildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "testenv-*")
		if err != nil {
			goBuildErr = err
			return
		}
		defer os.RemoveAll(dir)

		mainGo := filepath.Join(dir, "main.go")
		if err := os.WriteFile(mainGo, []byte("package main\nfunc main() {}\n"), 0644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("go", "build", "-o", os.DevNull, mainGo)
		cmd.Dir = dir
		if err := cmd.Run(); err != nil {
			goBuildErr = fmt.Errorf("%v: %v", cmd, err)
		}
	})

	if goBuildErr != nil {
		t.Helper()
		t.Skipf("skipping test: 'go build' not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

var (
	goBuildOnce sync.Once
	goBuildErr  error
)

// NeedsLocalhostNet skips t if networking does not work for ports opened
// with "localhost".
func NeedsLocalhostNet(t testing.TB) {
	switch runtime.GOOS {
	case "js", "wasip1":
		t.Skipf(`Listening on "localhost" fails on %s; see https://go.dev/issue/59718`, runtime.GOOS)
	}
}
