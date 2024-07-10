// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package semver

import (
	"testing"
)

func TestCanonicalize(t *testing.T) {
	for _, test := range []struct {
		v    string
		want string
	}{
		{"v1.2.3", "v1.2.3"},
		{"1.2.3", "v1.2.3"},
		{"go1.2.3", "v1.2.3"},
	} {
		got := canonicalizeSemverPrefix(test.v)
		if got != test.want {
			t.Errorf("want %s; got %s", test.want, got)
		}
	}
}

func TestGoTagToSemver(t *testing.T) {
	for _, test := range []struct {
		v    string
		want string
	}{
		{"go1.19", "v1.19.0"},
		{"go1.20-pre4", "v1.20.0-pre.4"},
	} {
		got := GoTagToSemver(test.v)
		if got != test.want {
			t.Errorf("want %s; got %s", test.want, got)
		}
	}
}

func TestLess(t *testing.T) {
	for _, test := range []struct {
		v1   string
		v2   string
		want bool
	}{
		{"go1.19", "go1.19", false},
		{"go1.19.1", "go1.19", false},
		{"v0.2.1", "v0.3.0", true},
		{"go1.12.2", "go1.18", true},
		{"v1.20.0-pre4", "v1.20.0-pre.4", false},
		{"v1.20.0-pre4", "v1.20.0-pre4.4", true},
	} {
		if got := Less(test.v1, test.v2); got != test.want {
			t.Errorf("want Less(%s, %s)=%t; got %t", test.v1, test.v2, test.want, got)
		}
	}
}
