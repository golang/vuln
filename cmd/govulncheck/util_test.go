// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"runtime/debug"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestIndent(t *testing.T) {
	for _, test := range []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"short", "hello", 2, "  hello"},
		{"multi", "mulit\nline\nstring", 1, " mulit\n line\n string"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := indent(test.s, test.n)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestGovulncheckVersion(t *testing.T) {
	bi := &debug.BuildInfo{
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "1234567890001234"},
			{Key: "vcs.time", Value: "2023-01-25T19:57:54Z"},
		},
	}

	want := "v0.0.0-123456789000-20230125195754"
	if got := govulncheckVersion(bi); got != want {
		t.Errorf("got %s; want %s", got, want)
	}
}
