// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package vulncheck

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/tools/go/packages/packagestest"
	"golang.org/x/vuln/internal/semver"
	"golang.org/x/vuln/vulncheck/internal/binscan"
)

// TODO: we build binary programatically, so what if the underlying tool chain changes?
func TestBinary(t *testing.T) {
	// TODO(#52160): investigate why Binary does not process plan9 binaries
	if !hasGoBuild() || runtime.GOOS == "plan9" {
		t.Skip("fails on android and plan9")
	}

	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "golang.org/entry",
			Files: map[string]interface{}{
				"main.go": `
			package main

			import (
				"archive/zip"
				"golang.org/cmod/c"
				"golang.org/bmod/bvuln"
			)

			func main() {
				c.C()
				bvuln.NoVuln() // no vuln use

				_, err := zip.OpenReader("file.zip")
				print(err)
			}
			`,
			}},
		{
			Name: "golang.org/cmod@v1.1.3",
			Files: map[string]interface{}{"c/c.go": `
			package c

			import (
				"golang.org/amod/avuln"
			)

			//go:noinline
			func C() {
				v := avuln.VulnData{}
				v.Vuln1() // vuln use
			}
			`},
		},
		{
			Name: "golang.org/amod@v1.1.3",
			Files: map[string]interface{}{"avuln/avuln.go": `
			package avuln

			type VulnData struct {}

			//go:noinline
			func (v VulnData) Vuln1() {}

			//go:noinline
			func (v VulnData) Vuln2() {}
			`},
		},
		{
			Name: "golang.org/bmod@v0.5.0",
			Files: map[string]interface{}{"bvuln/bvuln.go": `
			package bvuln

			//go:noinline
			func Vuln() {}

			//go:noinline
			func NoVuln() {}
			`},
		},
	})
	defer e.Cleanup()

	cmd := exec.Command("go", "build", "-o", "entry")
	cmd.Dir = e.Config.Dir
	cmd.Env = e.Config.Env
	out, err := cmd.CombinedOutput()
	if err != nil || len(out) > 0 {
		t.Fatalf("failed to build the binary %v %v", err, string(out))
	}

	bin, err := os.Open(filepath.Join(e.Config.Dir, "entry"))
	if err != nil {
		t.Fatalf("failed to access the binary %v", err)
	}
	defer bin.Close()

	// Test imports only mode
	cfg := &Config{
		Client:      testClient,
		ImportsOnly: true,
	}
	res, err := Binary(context.Background(), bin, cfg)
	if err != nil {
		t.Fatal(err)
	}

	hasGo := hasGoVersion(bin)
	// In importsOnly mode, vulnerable symbols
	// {avuln.VulnData.Vuln1, avuln.VulnData.Vuln2, bvuln.Vuln}
	// should be detected.
	wantVulns := []*Vuln{
		{Symbol: "Vuln", PkgPath: "golang.org/bmod/bvuln", ModPath: "golang.org/bmod"},
		{Symbol: "VulnData.Vuln1", PkgPath: "golang.org/amod/avuln", ModPath: "golang.org/amod"},
		{Symbol: "VulnData.Vuln2", PkgPath: "golang.org/amod/avuln", ModPath: "golang.org/amod"},
	}
	if hasGo {
		// If binary has recognizable Go version available,
		// then archive/zip.OpenReader should be detected too.
		wantVulns = append(wantVulns, &Vuln{Symbol: "OpenReader", PkgPath: "archive/zip", ModPath: "stdlib"})
	}

	diff := cmp.Diff(wantVulns, res.Vulns,
		cmpopts.IgnoreFields(Vuln{}, "OSV"),
		cmpopts.SortSlices(func(v1, v2 *Vuln) bool { return v1.Symbol < v2.Symbol }))
	if diff != "" {
		t.Errorf("vulns mismatch (-want, +got)\n%s", diff)
	}

	// Test the symbols (non-import mode)
	cfg = &Config{Client: testClient}
	res, err = Binary(context.Background(), bin, cfg)
	if err != nil {
		t.Fatal(err)
	}

	wantVulns = []*Vuln{
		{Symbol: "VulnData.Vuln1", PkgPath: "golang.org/amod/avuln", ModPath: "golang.org/amod"},
	}
	if hasGo {
		// If binary has recognizable Go version available,
		// then archive/zip.OpenReader should be detected too.
		wantVulns = append(wantVulns, &Vuln{Symbol: "OpenReader", PkgPath: "archive/zip", ModPath: "stdlib"})
	}

	diff = cmp.Diff(wantVulns, res.Vulns,
		cmpopts.IgnoreFields(Vuln{}, "OSV"),
		cmpopts.SortSlices(func(v1, v2 *Vuln) bool { return v1.Symbol < v2.Symbol }))
	if diff != "" {
		t.Errorf("vulns mismatch (-want, +got)\n%s", diff)
	}

	// Check that the binary's modules are returned.
	// The list does not include the module binary itself.
	wantMods := []*Module{
		{Path: "golang.org/amod", Version: "v1.1.3"},
		{Path: "golang.org/bmod", Version: "v0.5.0"},
		{Path: "golang.org/cmod", Version: "v1.1.3"},
		stdlibModule,
	}
	gotMods := res.Modules
	sort.Slice(gotMods, func(i, j int) bool { return gotMods[i].Path < gotMods[j].Path })
	if diff := cmp.Diff(wantMods, gotMods, cmpopts.IgnoreFields(Module{}, "Dir")); diff != "" {
		t.Errorf("modules mismatch (-want, +got):\n%s", diff)
	}
}

// hasGoBuild reports whether the current system can build programs with “go build”
// and then run them with os.StartProcess or exec.Command.
//
// Duplicated from std/internal/testenv
func hasGoBuild() bool {
	if os.Getenv("GO_GCFLAGS") != "" {
		return false
	}
	switch runtime.GOOS {
	case "android", "js", "ios":
		return false
	}
	return true
}

func hasGoVersion(exe io.ReaderAt) bool {
	_, _, bi, _ := binscan.ExtractPackagesAndSymbols(exe)
	return semver.GoTagToSemver(bi.GoVersion) != ""
}
