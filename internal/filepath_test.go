// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"path/filepath"
	"testing"
)

func TestAbsRelShorter(t *testing.T) {
	thisFileAbs, _ := filepath.Abs("filepath_test.go")

	for _, test := range []struct {
		l    string
		want string
	}{
		{"filepath_test.go", "filepath_test.go"},
		{thisFileAbs, "filepath_test.go"},
	} {
		if got := AbsRelShorter(test.l); got != test.want {
			t.Errorf("want %s; got %s", test.want, got)
		}
	}
}
