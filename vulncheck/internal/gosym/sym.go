// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosym

import (
	"strings"

	sv "golang.org/x/mod/semver"
	"golang.org/x/vuln/internal/semver"
)

const (
	funcSymNameGo119Lower string = "go.func.*"
	funcSymNameGo120      string = "go:func.*"
)

// FuncSymName returns symbol name for Go functions
// used in binaries based on Go version. Supported
// Go versions are 1.18, 1.19, and 1.20. Otherwise,
// returns an empty string.
func FuncSymName(goVersion string) string {
	// Support devel goX.Y...
	v := strings.TrimPrefix(goVersion, "devel ")
	v = semver.GoTagToSemver(v)
	mm := sv.MajorMinor(v)
	if mm == "v1.18" || mm == "v1.19" {
		return funcSymNameGo119Lower
	} else if mm == "v1.20" {
		return funcSymNameGo120
	} else if v == "" && strings.HasPrefix(goVersion, "devel") {
		// We currently don't have a direct way of mapping
		// Go versions of the form devel <hash> to semver,
		// so we map it to the most recent supported major
		// Go version, which is currently go1.20.
		return funcSymNameGo120
	}
	return ""
}
