// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

// Command govulncheck reports known vulnerabilities filed in a vulnerability database
// (see https://golang.org/design/draft-vulndb) that affect a given package or binary.
//
// It uses static analysis or the binary's symbol table to narrow down reports to only
// those that potentially affect the application.
//
// # WARNING WARNING WARNING
//
// govulncheck is still experimental and neither its output or the vulnerability
// database should be relied on to be stable or comprehensive.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"go/build"
	"log"
	"os"
	"sort"
	"strings"

	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/cmd/govulncheck/internal/govulncheck"
	"golang.org/x/vuln/vulncheck"
)

var (
	jsonFlag    = flag.Bool("json", false, "")
	verboseFlag = flag.Bool("v", false, "")
	testsFlag   = flag.Bool("tests", false, "")
	htmlFlag    = flag.Bool("html", false, "")
)

const usage = `govulncheck: identify known vulnerabilities by call graph traversal.

Usage:

	govulncheck [flags] {package pattern...}

	govulncheck [flags] {binary path}

Flags:

	-json	Print vulnerability findings in JSON format.

	-html	Generate HTML with the vulnerability findings.

	-tags	Comma-separated list of build tags.

	-tests	Boolean flag indicating if test files should be analyzed too.

govulncheck can be used with either one or more package patterns (i.e. golang.org/x/crypto/...
or ./...) or with a single path to a Go binary. In the latter case module and symbol
information will be extracted from the binary in order to detect vulnerable symbols.

The environment variable GOVULNDB can be set to a comma-separated list of vulnerability
database URLs, with http://, https://, or file:// protocols. Entries from multiple
databases are merged.
`

func init() {
	flag.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
}

func main() {
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if len(flag.Args()) == 0 {
		die("%s", usage)
	}

	dbs := []string{"https://vuln.go.dev"}
	if GOVULNDB := os.Getenv("GOVULNDB"); GOVULNDB != "" {
		dbs = strings.Split(GOVULNDB, ",")
	}
	dbClient, err := client.NewClient(dbs, client.Options{
		HTTPCache: govulncheck.DefaultCache(),
	})
	if err != nil {
		die("govulncheck: %s", err)
	}
	vcfg := &vulncheck.Config{Client: dbClient}
	ctx := context.Background()

	patterns := flag.Args()
	var (
		r    *vulncheck.Result
		pkgs []*vulncheck.Package
	)
	if len(patterns) == 1 && isFile(patterns[0]) {
		f, err := os.Open(patterns[0])
		if err != nil {
			die("govulncheck: %v", err)
		}
		defer f.Close()
		r, err = vulncheck.Binary(ctx, f, vcfg)
		if err != nil {
			die("govulncheck: %v", err)
		}
	} else {
		cfg := &packages.Config{
			Tests:      *testsFlag,
			BuildFlags: []string{fmt.Sprintf("-tags=%s", strings.Join(build.Default.BuildTags, ","))},
		}
		pkgs, err = loadPackages(cfg, patterns)
		if err != nil {
			die("govulncheck: %v", err)
		}
		r, err = govulncheck.Source(ctx, pkgs, dbClient)
		if err != nil {
			die("govulncheck: %v", err)
		}
	}
	if *jsonFlag {
		writeJSON(r)
	} else {
		// set of top-level packages, used to find representative symbols
		ci := govulncheck.GetCallInfo(r, pkgs)
		if *htmlFlag {
			if err := html(os.Stdout, r, ci); err != nil {
				die("writing HTML: %v", err)
			}
		} else {
			writeText(r, ci)
		}
	}
	exitCode := 0
	// Following go vet, fail with 3 if there are findings (in this case, vulns).
	if len(r.Vulns) > 0 {
		exitCode = 3
	}
	os.Exit(exitCode)
}

func writeJSON(r *vulncheck.Result) {
	b, err := json.MarshalIndent(r, "", "\t")
	if err != nil {
		die("govulncheck: %s", err)
	}
	os.Stdout.Write(b)
	fmt.Println()
}

func writeText(r *vulncheck.Result, ci *govulncheck.CallInfo) {

	const labelWidth = 16
	line := func(label, text string) {
		fmt.Printf("%-*s%s\n", labelWidth, label, text)
	}
	for _, vg := range ci.VulnGroups {
		// All the vulns in vg have the same PkgPath, ModPath and OSV.
		// All have a non-zero CallSink.
		v0 := vg[0]
		line("package:", v0.PkgPath)
		line("your version:", ci.ModuleVersions[v0.ModPath])
		line("fixed version:", "v"+govulncheck.LatestFixed(v0.OSV.Affected))
		var summaries []string
		for _, v := range vg {
			if css := ci.CallStacks[v]; len(css) > 0 {
				if sum := govulncheck.SummarizeCallStack(css[0], ci.TopPackages, v.PkgPath); sum != "" {
					summaries = append(summaries, sum)
				}
			}
		}
		if len(summaries) > 0 {
			sort.Strings(summaries)
			summaries = compact(summaries)
			line("sample call stacks:", "")
			for _, s := range summaries {
				line("", s)
			}
		}
		line("reference:", fmt.Sprintf("https://pkg.go.dev/vuln/%s", v0.OSV.ID))
		desc := strings.Split(wrap(v0.OSV.Details, 80-labelWidth), "\n")
		for i, l := range desc {
			if i == 0 {
				line("description:", l)
			} else {
				line("", l)
			}
		}
		fmt.Println()
	}
}

func isFile(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !s.IsDir()
}

func loadPackages(cfg *packages.Config, patterns []string) ([]*vulncheck.Package, error) {
	if *verboseFlag {
		log.Println("loading packages...")
	}
	pkgs, err := govulncheck.LoadPackages(cfg, patterns...)
	if err != nil {
		return nil, err
	}
	if *verboseFlag {
		log.Printf("\t%d loaded packages\n", len(pkgs))
	}
	return pkgs, nil
}

// compact replaces consecutive runs of equal elements with a single copy.
// This is like the uniq command found on Unix.
// compact modifies the contents of the slice s; it does not create a new slice.
//
// Modified (generics removed) from exp/slices/slices.go.
func compact(s []string) []string {
	if len(s) == 0 {
		return s
	}
	i := 1
	last := s[0]
	for _, v := range s[1:] {
		if v != last {
			s[i] = v
			i++
			last = v
		}
	}
	return s[:i]
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
