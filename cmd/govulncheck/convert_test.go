// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal/testenv"
	"golang.org/x/vuln/internal/web"
	"golang.org/x/vuln/scan"
)

func TestConvert(t *testing.T) {
	testenv.NeedsGoBuild(t)

	testDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	vulndbDir, err := filepath.Abs(filepath.Join(testDir, "testdata", "vulndb-v1"))
	if err != nil {
		t.Fatal(err)
	}
	govulndbURI, err := web.URLFromFilePath(vulndbDir)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}

	ctx := context.Background()
	modDir := filepath.Join(testDir, "testdata", "modules", "vuln")
	jsonCmd := scan.Command(ctx, "-db", govulndbURI.String(), "-C", modDir, "-json", ".")

	jsonOutput, pw := io.Pipe()
	jsonCmd.Stdout = pw
	if err := jsonCmd.Start(); err != nil {
		t.Fatal(err)
	}
	convertCmd := scan.Command(ctx, "-db", govulndbURI.String(), "-mode", "convert")
	convertCmd.Stdin = jsonOutput
	var b bytes.Buffer
	convertCmd.Stdout = &b
	if err := convertCmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := jsonCmd.Wait(); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	if err := convertCmd.Wait(); err != nil {
		t.Fatal(err)
	}
	got := b.Bytes()
	for _, fix := range fixups {
		got = fix.apply(got)
	}

	want, err := os.ReadFile("testdata/convert.txt")
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(string(got), string(want)); diff != "" {
		t.Fatalf("mismatch (-want, +got): %s", diff)
	}
}
