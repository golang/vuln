// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"strings"
)

// wrap wraps s to fit in maxWidth by breaking it into lines at whitespace. If a
// single word is longer than maxWidth, it is retained as its own line.
func wrap(s string, maxWidth int) string {
	var b strings.Builder
	w := 0

	for _, f := range strings.Fields(s) {
		if w > 0 && w+len(f)+1 > maxWidth {
			b.WriteByte('\n')
			w = 0
		}
		if w != 0 {
			b.WriteByte(' ')
			w++
		}
		b.WriteString(f)
		w += len(f)
	}
	return b.String()
}
