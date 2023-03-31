// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"context"
	"io"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/govulncheck"
)

// doGovulncheck performs main govulncheck functionality and exits the
// program upon success with an appropriate exit status. Otherwise,
// returns an error.
func doGovulncheck(ctx context.Context, cfg *config, w io.Writer) error {
	dir := filepath.FromSlash(cfg.dir)
	var err error
	cfg.Client, err = client.NewClient(cfg.db, client.Options{})
	if err != nil {
		return err
	}

	preamble := newPreamble(ctx, cfg)
	var output govulncheck.Handler
	switch {
	case cfg.json:
		output = govulncheck.NewJSONHandler(w)
	default:
		output = NewTextHandler(w)
	}

	// Write the introductory message to the user.
	if err := output.Preamble(preamble); err != nil {
		return err
	}

	var res *govulncheck.Result
	switch cfg.analysis {
	case govulncheck.AnalysisSource:
		res, err = runSource(ctx, output, cfg, dir)
	case govulncheck.AnalysisBinary:
		res, err = runBinary(ctx, output, cfg)
	}
	if err != nil {
		return err
	}

	// For each vulnerability, queue it to be written to the output.
	for _, v := range res.Vulns {
		if err := output.Vulnerability(v); err != nil {
			return err
		}
	}
	if err := output.Flush(); err != nil {
		return err
	}
	if containsAffectedVulnerabilities(res) {
		return ErrVulnerabilitiesFound
	}
	return nil
}

func containsAffectedVulnerabilities(r *govulncheck.Result) bool {
	for _, v := range r.Vulns {
		if IsCalled(v) {
			return true
		}
	}
	return false
}

func newPreamble(ctx context.Context, cfg *config) *govulncheck.Preamble {
	preamble := govulncheck.Preamble{
		DB:       cfg.db,
		Analysis: cfg.analysis,
		Mode:     govulncheck.ModeCompact,
	}
	if cfg.verbose {
		preamble.Mode = govulncheck.ModeVerbose
	}
	if cfg.analysis == govulncheck.AnalysisSource {
		// The Go version is only relevant for source analysis, so omit it for
		// binary mode.
		if v, err := internal.GoEnv("GOVERSION"); err == nil {
			preamble.GoVersion = v
		}
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		preamble.GovulncheckVersion = scannerVersion(bi)
	}
	if mod, err := cfg.Client.LastModifiedTime(ctx); err == nil {
		preamble.DBLastModified = &mod
	}
	return &preamble
}

// scannerVersion reconstructs the current version of
// this binary used from the build info.
func scannerVersion(bi *debug.BuildInfo) string {
	var revision, at string
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			revision = s.Value
		}
		if s.Key == "vcs.time" {
			at = s.Value
		}
	}
	buf := strings.Builder{}
	if bi.Path != "" {
		buf.WriteString(path.Base(bi.Path))
		buf.WriteString("@")
	}
	// TODO: we manually change this after every
	// minor revision? bi.Main.Version seems not
	// to work (see #29228).
	buf.WriteString("v0.0.0")
	if revision != "" {
		buf.WriteString("-")
		buf.WriteString(revision[:12])
	}
	if at != "" {
		// commit time is of the form 2023-01-25T19:57:54Z
		p, err := time.Parse(time.RFC3339, at)
		if err == nil {
			buf.WriteString("-")
			buf.WriteString(p.Format("20060102150405"))
		}
	}
	return buf.String()
}
