// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosym

import (
	"testing"
)

func TestFuncSymName(t *testing.T) {
	for _, test := range []struct {
		v    string
		want string
	}{
		{"go1.18", "go.func.*"},
		{"go1.19", "go.func.*"},
		{"devel go1.19", "go.func.*"},
		{"go1.19-pre4", "go.func.*"},
		{"go1.20", "go:func.*"},
		{"devel bd56cb90a72e6725e", "go:func.*"},
	} {
		if got := FuncSymName(test.v); got != test.want {
			t.Errorf("got %s; want %s", got, test.want)
		}
	}
}
