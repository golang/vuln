// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !testmode
// +build !testmode

package internal

import (
	"encoding/json"
	"os/exec"
)

// GoEnv returns the value for key in `go env`. In
// the unlikely case that `go env` fails, prints an
// error message and returns an empty string.
func GoEnv(key string) string {
	out, err := exec.Command("go", "env", "-json", key).Output()
	if err != nil {
		return ""
	}
	env := make(map[string]string)
	if err := json.Unmarshal(out, &env); err != nil {
		return ""
	}
	return env[key]
}
