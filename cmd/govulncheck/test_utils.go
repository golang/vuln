// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// copyTestCase copies the test case at dir into a
// temporary directory. The created files have 0644
// permission and directories 0755. It does not create
// symlinks.
func copyTestCase(dir string, t *testing.T) string {
	newDir, err := filepath.Abs(t.TempDir())
	if err != nil {
		t.Fatalf("failed to copy test case %s: cannot create root %v", dir, err)
	}

	if err := copyDir(dir, newDir); err != nil {
		t.Fatalf("failed to copy test case %s: copy failure %v", dir, err)
	}
	return newDir
}

func copyDir(srcDir, destDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		src := filepath.Join(srcDir, entry.Name())
		dest := filepath.Join(destDir, entry.Name())

		fileInfo, err := os.Stat(src)
		if err != nil {
			return err
		}

		switch fileInfo.Mode() & os.ModeType {
		case os.ModeDir:
			if err := os.MkdirAll(dest, 0755); err != nil {
				return err
			}
			if err := copyDir(src, dest); err != nil {
				return err
			}
		default:
			if err := copyFile(src, dest); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyFile(src, dest string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dest, b, 0644)
}

type fixup struct {
	Pattern     string `json:"pattern,omitempty"`
	Replace     string `json:"replace,omitempty"`
	compiled    *regexp.Regexp
	replaceFunc func(b []byte) []byte
}

func (f *fixup) init() {
	f.compiled = regexp.MustCompile(f.Pattern)
}

func (f *fixup) apply(data []byte) []byte {
	if f.replaceFunc != nil {
		return f.compiled.ReplaceAllFunc(data, f.replaceFunc)
	}
	return f.compiled.ReplaceAll(data, []byte(f.Replace))
}

// loadFixups loads and initializes fixups from path. If there is
// nothing at path, returns nil, nil.
func loadFixups(path string) ([]fixup, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil // no fixups, which is ok
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fixups []fixup
	if err := json.Unmarshal(b, &fixups); err != nil {
		return nil, err
	}
	for i := range fixups {
		fixups[i].init()
	}
	return fixups, nil
}
