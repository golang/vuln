// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"path"
	"strings"

	"golang.org/x/mod/module"
)

// vcsHostWithThreeElementRepoName returns true when the hostname
// has three elements like hostname/account/project.
func vcsHostWithThreeElementRepoName(hostname string) bool {
	switch hostname {
	case
		"git.sr.ht",
		"gitea.com",
		"gitee.com",
		"gitlab.com",
		"hg.sr.ht",
		"bitbucket.org",
		"github.com",
		"golang.org",
		"launchpad.net":
		return true
	default:
		return false
	}
}

// candidateModulePaths returns the potential module paths that could contain
// the fullPath, from longest to shortest. It returns nil if no valid module
// paths can be constructed.
func candidateModulePaths(fullPath string) []string {
	if stdlibContains(fullPath) {
		if err := module.CheckImportPath(fullPath); err != nil {
			return nil
		}
		return []string{"std"}
	}
	var r []string
	for p := fullPath; p != "." && p != "/"; p = path.Dir(p) {
		if err := module.CheckPath(p); err != nil {
			continue
		}
		r = append(r, p)
	}
	if len(r) == 0 {
		return nil
	}
	if !vcsHostWithThreeElementRepoName(r[len(r)-1]) {
		return r
	}
	if len(r) < 3 {
		return nil
	}
	return r[:len(r)-2]
}

// stdlibContains reports whether the given import path could be part of the Go standard library,
// by reporting whether the first component lacks a '.'.
func stdlibContains(path string) bool {
	if i := strings.IndexByte(path, '/'); i != -1 {
		path = path[:i]
	}
	return !strings.Contains(path, ".")
}
