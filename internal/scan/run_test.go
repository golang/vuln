// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"runtime/debug"
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
