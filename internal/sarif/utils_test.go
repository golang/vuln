// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sarif

import "testing"

func TestList(t *testing.T) {
	for _, tc := range []struct {
		elems []string
		want  string
	}{
		{nil, ""},
		{[]string{"1"}, "1"},
		{[]string{"1", "2"}, "1 and 2"},
		{[]string{"1", "2", "3"}, "1, 2, and 3"},
		{[]string{"1", "2", "3", "4"}, "1, 2, 3, and 4"},
	} {
		got := list(tc.elems)
		if tc.want != got {
			t.Errorf("want %s; got %s", tc.want, got)
		}
	}
}
