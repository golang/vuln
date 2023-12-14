// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sarif

import (
	"strings"
)

func choose(s1, s2 string, cond bool) string {
	if cond {
		return s1
	}
	return s2
}

func list(elems []string) string {
	l := len(elems)
	if l == 0 {
		return ""
	}
	if l == 1 {
		return elems[0]
	}

	cList := strings.Join(elems[:l-1], ", ")
	return cList + choose("", ",", l == 2) + " and " + elems[l-1]
}
