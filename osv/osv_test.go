// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package osv_test

import (
	"testing"

	"golang.org/x/vuln/internal/test"
)

func TestImports(t *testing.T) {
	test.VerifyImports(t) // no non stdlib imports allowed
}
