// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testenv

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"
)

// HasExec reports whether the current system can start new processes
// using os.StartProcess or (more commonly) exec.Command.
func HasExec() bool {
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
		return true

	case "ios", "js", "wasip1":
		// ios has an exec syscall but on real iOS devices it might return a
		// permission error. In an emulated environment (such as a Corellium host)
		// it might succeed, so try it and find out.
		//
		// As of 2023-04-19 wasip1 and js don't have exec syscalls at all, but we
		// may as well use the same path so that this branch can be tested without
		// an ios environment.
		fallthrough

	default:
		tryExecOnce.Do(func() {
			exe, err := os.Executable()
			if err != nil {
				tryExecErr = err
				return
			}
			if flag.Lookup("test.list") == nil {
				// We found the executable, but we don't know how to run it in a way
				// that should succeed without side-effects. Just forget it.
				tryExecErr = errors.New("can't check for exec support: current process is not a test")
				return
			}
			// We know that a test executable exists and can run, because we're
			// running it now. Use it to check for overall exec support, but be sure
			// to remove any environment variables that might trigger non-default
			// behavior in a custom TestMain.
			cmd := exec.Command(exe, "-test.list=^$")
			cmd.Env = []string{}
			if err := cmd.Run(); err != nil {
				tryExecErr = err
			}
			tryExecOk = true
		})
		return tryExecOk
	}
}

var (
	tryExecOnce sync.Once
	tryExecOk   bool
	tryExecErr  error
)

// NeedsExec checks that the current system can start new processes
// using os.StartProcess or (more commonly) exec.Command.
// If not, NeedsExec calls t.Skip with an explanation.
func NeedsExec(t testing.TB) {
	if !HasExec() {
		t.Helper()
		t.Skipf("skipping test: cannot exec subprocess on %s/%s: %v", runtime.GOOS, runtime.GOARCH, tryExecErr)
	}
}

func HasGoBuild() (bool, error) {
	hasGoBuildOnce.Do(func() {
		if !HasExec() {
			hasGoBuildErr = tryExecErr
			return
		}

		// Also ensure that that GOROOT includes a compiler: 'go' commands
		// don't in general work without it, and some builders
		// (such as android-amd64-emu) seem to lack it in the test environment.
		cmd := exec.Command("go", "tool", "-n", "compile")
		stderr := new(bytes.Buffer)
		stderr.Write([]byte("\n"))
		cmd.Stderr = stderr
		out, err := cmd.Output()
		if err != nil {
			hasGoBuildErr = err
			return
		}
		if _, err := exec.LookPath(string(bytes.TrimSpace(out))); err != nil {
			hasGoBuildErr = err
			return
		}
		hasGoBuild = true
	})

	return hasGoBuild, hasGoBuildErr
}

var (
	hasGoBuildOnce sync.Once
	hasGoBuild     bool
	hasGoBuildErr  error
)

func NeedsGoBuild(t testing.TB) {
	if hgb, _ := HasGoBuild(); !hgb {
		t.Helper()
		t.Skipf("skipping test: 'go build' not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

// NeedsLocalhostNet skips t if networking does not work for ports opened
// with "localhost".
func NeedsLocalhostNet(t testing.TB) {
	switch runtime.GOOS {
	case "js", "wasip1":
		t.Skipf(`Listening on "localhost" fails on %s; see https://go.dev/issue/59718`, runtime.GOOS)
	}
}
