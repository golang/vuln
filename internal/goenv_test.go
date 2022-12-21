// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"testing"
)

func TestGoEnv(t *testing.T) {
	for _, key := range []string{"GOVERSION", "GOROOT", "GOPATH", "GOMODCACHE"} {
		if GoEnv(key) == "" {
			t.Errorf("want something for go env %s; got nothing", key)
		}
	}
}
