// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"testing"
)

func TestIsExported(t *testing.T) {
	for _, tc := range []struct {
		symbol string
		want   bool
	}{
		{"foo", false},
		{"Foo", true},
		{"x.foo", false},
		{"X.foo", false},
		{"x.Foo", true},
		{"X.Foo", true},
	} {
		tc := tc
		t.Run(tc.symbol, func(t *testing.T) {
			if got := isExported(tc.symbol); tc.want != got {
				t.Errorf("want %t; got %t", tc.want, got)
			}
		})
	}
}
