// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package vulncheck

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"golang.org/x/tools/go/packages/packagestest"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/semver"
	"golang.org/x/vuln/internal/testenv"
	"golang.org/x/vuln/internal/vulncheck/internal/buildinfo"
)

// TODO: we build binary programatically, so what if the underlying tool chain changes?
func TestBinary(t *testing.T) {
	testenv.NeedsGoBuild(t)

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

			func (v VulnData) Vuln1() {
				print("vuln1")
			}

			func (v VulnData) Vuln2() {
				print("vuln2")
			}
			`},
		},
		{
			Name: "golang.org/bmod@v0.5.0",
			Files: map[string]interface{}{"bvuln/bvuln.go": `
			package bvuln

			func Vuln() {
				print("vuln")
			}

			func NoVuln() {
				print("novuln")
			}
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

	c, err := newTestClient()
	if err != nil {
		t.Fatal(err)
	}

	// Test imports only mode
	cfg := &govulncheck.Config{ScanLevel: "package"}
	res, err := Binary(context.Background(), bin, cfg, c)
	if err != nil {
		t.Fatal(err)
	}

	goversion := getGoVersion(bin)
	// In importsOnly mode, vulnerable symbols
	// {avuln.VulnData.Vuln1, avuln.VulnData.Vuln2, bvuln.Vuln}
	// should be detected.
	wantVulns := []*testVuln{
		{Symbol: "Vuln", PkgPath: "golang.org/bmod/bvuln", ModPath: "golang.org/bmod"},
		{Symbol: "VulnData.Vuln1", PkgPath: "golang.org/amod/avuln", ModPath: "golang.org/amod"},
		{Symbol: "VulnData.Vuln2", PkgPath: "golang.org/amod/avuln", ModPath: "golang.org/amod"},
	}
	if goversion != "" {
		// If binary has recognizable Go version available,
		// then archive/zip.OpenReader should be detected too.
		wantVulns = append(wantVulns, &testVuln{Symbol: "OpenReader", PkgPath: "archive/zip", ModPath: "stdlib"})
	}

	compareVulns(t, wantVulns, res)

	// Test the symbols (non-import mode)
	cfg.ScanLevel = "symbol"
	res, err = Binary(context.Background(), bin, cfg, c)
	if err != nil {
		t.Fatal(err)
	}

	wantVulns = []*testVuln{
		{Symbol: "VulnData.Vuln1", PkgPath: "golang.org/amod/avuln", ModPath: "golang.org/amod"},
	}
	if goversion != "" {
		// If binary has recognizable Go version available,
		// then archive/zip.OpenReader should be detected too.
		wantVulns = append(wantVulns, &testVuln{Symbol: "OpenReader", PkgPath: "archive/zip", ModPath: "stdlib"})
	}

	compareVulns(t, wantVulns, res)
}

func getGoVersion(exe io.ReaderAt) string {
	_, _, bi, _ := buildinfo.ExtractPackagesAndSymbols(exe)
	return semver.GoTagToSemver(bi.GoVersion)
}

// Test58509 is supposed to test issue #58509 where a whole
// vulnerable function is deleted from the binary so we
// cannot detect its presence.
//
// Note: the issue is still not addressed and the test
// expectations are set to fail once it gets addressed.
func Test58509(t *testing.T) {
	testenv.NeedsGoBuild(t)

	vulnLib := `package bvuln

%s debug = true

func Vuln() {
	if debug {
		return
	}
	print("vuln")
}`

	for _, tc := range []struct {
		gl   string
		want []*testVuln
	}{
		{"const", nil}, // TODO(https://go.dev/issue/58509): change expectations once issue is addressed
		{"var", []*testVuln{{Symbol: "Vuln", PkgPath: "golang.org/bmod/bvuln", ModPath: "golang.org/bmod"}}},
	} {
		tc := tc
		t.Run(tc.gl, func(t *testing.T) {
			e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
				{
					Name: "golang.org/entry",
					Files: map[string]interface{}{
						"main.go": `
			package main

			import (
				"golang.org/bmod/bvuln"
			)

			func main() {
				bvuln.Vuln()
			}
			`,
					}},
				{
					Name:  "golang.org/bmod@v0.5.0",
					Files: map[string]interface{}{"bvuln/bvuln.go": fmt.Sprintf(vulnLib, tc.gl)},
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

			c, err := newTestClient()
			if err != nil {
				t.Fatal(err)
			}

			cfg := &govulncheck.Config{ScanLevel: "symbol"}
			res, err := Binary(context.Background(), bin, cfg, c)
			if err != nil {
				t.Fatal(err)
			}

			compareVulns(t, tc.want, res)
		})
	}
}

type testVuln struct {
	Symbol  string
	PkgPath string
	ModPath string
}

func compareVulns(t *testing.T, want []*testVuln, res *Result) {
	if len(want) != len(res.Vulns) {
		t.Error("want", len(want), "vulnerabilities, got", len(res.Vulns))
		return
	}
	sort.Slice(want, func(i, j int) bool { return want[i].Symbol < want[j].Symbol })
	sort.Slice(res.Vulns, func(i, j int) bool { return res.Vulns[i].Symbol < res.Vulns[j].Symbol })
	for i, want := range want {
		got := res.Vulns[i]
		if want.Symbol != got.Symbol {
			t.Error("[", i, "] want", want.Symbol, ", got", got.Symbol)
		}
		if want.PkgPath != got.ImportSink.PkgPath {
			t.Error("[", i, "] want", want.ModPath, ", got", got.ImportSink.Module.Path)
		}
		if want.ModPath != got.ImportSink.Module.Path {
			t.Error("[", i, "] want", want.ModPath, ", got", got.ImportSink.Module.Path)
		}
	}
}
