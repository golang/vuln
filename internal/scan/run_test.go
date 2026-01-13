// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"bytes"
	"context"
	"runtime/debug"
	"strings"
	"testing"
)

func TestGovulncheckVersion(t *testing.T) {
	bi := &debug.BuildInfo{
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "1234567890001234"},
			{Key: "vcs.time", Value: "2023-01-25T19:57:54Z"},
		},
	}

	want := "v0.0.0-123456789000-20230125195754"
	got := &config{}
	scannerVersion(got, bi)
	if got.ScannerVersion != want {
		t.Errorf("got %s; want %s", got.ScannerVersion, want)
	}
}

func TestRunGovulncheck_NoPatternsError(t *testing.T) {
	ctx := context.Background()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	err := RunGovulncheck(ctx, nil, nil, stdout, stderr, []string{})
	if err == nil {
		t.Fatal("expected RunGovulncheck to return an error for missing patterns, got nil")
	}

	wantMsg := "no package patterns provided"
	if !strings.Contains(err.Error(), wantMsg) {
		t.Errorf("got error: %v; want error containing %q", err, wantMsg)
	}
}

func TestRunGovulncheck_ModuleModeNoPatterns(t *testing.T) {
	ctx := context.Background()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	// ScanLevelModule does not require packages, so it should not error out on empty patterns.
	err := RunGovulncheck(ctx, nil, nil, stdout, stderr, []string{"-scan", "module"})

	if err != nil && strings.Contains(err.Error(), "no package patterns provided") {
		t.Errorf("unexpected 'no package patterns' error in module mode: %v", err)
	}
}
