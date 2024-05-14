// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"context"
	"fmt"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/vulncheck"
)

// runSource reports vulnerabilities that affect the analyzed packages.
//
// Vulnerabilities can be called (affecting the package, because a vulnerable
// symbol is actually exercised) or just imported by the package
// (likely having a non-affecting outcome).
func runSource(ctx context.Context, handler govulncheck.Handler, cfg *config, client *client.Client, dir string) (err error) {
	defer derrors.Wrap(&err, "govulncheck")

	if cfg.ScanLevel.WantPackages() && len(cfg.patterns) == 0 {
		return nil // don't throw an error here
	}
	if !gomodExists(dir) {
		return errNoGoMod
	}
	graph := vulncheck.NewPackageGraph(cfg.GoVersion)
	pkgConfig := &packages.Config{
		Dir:   dir,
		Tests: cfg.test,
		Env:   cfg.env,
	}
	if err := graph.LoadPackagesAndMods(pkgConfig, cfg.tags, cfg.patterns, cfg.ScanLevel == govulncheck.ScanLevelSymbol); err != nil {
		if isGoVersionMismatchError(err) {
			return fmt.Errorf("%v\n\n%v", errGoVersionMismatch, err)
		}
		return fmt.Errorf("loading packages: %w", err)
	}

	if err := handler.Progress(sourceProgressMessage(graph, cfg.ScanLevel)); err != nil {
		return err
	}

	if cfg.ScanLevel.WantPackages() && len(graph.TopPkgs()) == 0 {
		return nil // early exit
	}
	return vulncheck.Source(ctx, handler, &cfg.Config, client, graph)
}

// sourceProgressMessage returns a string of the form
//
//	"Scanning your code and P packages across M dependent modules for known vulnerabilities..."
//
// P is the number of strictly dependent packages of
// graph.TopPkgs() and Y is the number of their modules.
// If P is 0, then the following message is returned
//
//	"No packages matching the provided pattern."
func sourceProgressMessage(graph *vulncheck.PackageGraph, mode govulncheck.ScanLevel) *govulncheck.Progress {
	var pkgsPhrase, modsPhrase string
	mods := uniqueAnalyzableMods(graph)
	if mode.WantPackages() {
		if len(graph.TopPkgs()) == 0 {
			// The package pattern is valid, but no packages are matching.
			// Example is pkg/strace/... (see #59623).
			return &govulncheck.Progress{Message: "No packages matching the provided pattern."}
		}
		pkgs := len(graph.DepPkgs())
		pkgsPhrase = fmt.Sprintf(" and %d package%s", pkgs, choose(pkgs != 1, "s", ""))
	}
	modsPhrase = fmt.Sprintf(" %d dependent module%s", mods, choose(mods != 1, "s", ""))

	msg := fmt.Sprintf("Scanning your code%s across%s for known vulnerabilities...", pkgsPhrase, modsPhrase)
	return &govulncheck.Progress{Message: msg}
}

// uniqueAnalyzableMods returns the number of unique modules
// that are analyzable. Those are basically all modules except
// those that are replaced. The latter won't be analyzed as
// their code is never reachable.
func uniqueAnalyzableMods(graph *vulncheck.PackageGraph) int {
	replaced := 0
	mods := graph.Modules()
	for _, m := range mods {
		if m.Replace == nil {
			continue
		}
		if m.Path == m.Replace.Path {
			// If the replacing path is the same as
			// the one being replaced, then only one
			// of these modules is in mods.
			continue
		}
		replaced++
	}
	return len(mods) - replaced - 1 // don't include stdlib
}
