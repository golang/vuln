// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"testing"

	"golang.org/x/vuln/internal/testenv"
)

func TestGoEnv(t *testing.T) {
	testenv.NeedsGoEnv(t)

	for _, key := range []string{"GOVERSION", "GOROOT", "GOPATH", "GOMODCACHE"} {
		if val, err := GoEnv(key); val == "" {
			t.Errorf("want something for go env %s; got nothing", key)
		} else if err != nil {
			t.Errorf("unexpected error for go env %s: %v", key, err)
		}
	}
}

func TestGoEnvNonVariable(t *testing.T) {
	testenv.NeedsGoEnv(t)

	key := "NOT_A_GO_ENV_VARIABLE"
	if val, err := GoEnv(key); val != "" {
		t.Errorf("expected nothing for go env %s; got %s", key, val)
	} else if err != nil {
		t.Errorf("unexpected error for go env %s: %v", key, err)
	}
}

func TestGoEnvErr(t *testing.T) {
	testenv.NeedsGoEnv(t)

	key := "--not-a-flag"
	if val, err := GoEnv(key); err == nil {
		t.Errorf("wanted an error from go env %s; got value %q", key, val)
	}
}
