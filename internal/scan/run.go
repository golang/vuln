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
func doGovulncheck(ctx context.Context, w io.Writer, args []string) error {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}

	cfg.Client, err = client.NewClient(cfg.db, nil)
	if err != nil {
		return err
	}

	config := newConfig(ctx, cfg)
	var handler govulncheck.Handler
	switch {
	case cfg.json:
		handler = govulncheck.NewJSONHandler(w)
	default:
		handler = NewTextHandler(w, cfg.mode == modeSource, cfg.verbose)
	}

	// Write the introductory message to the user.
	if err := handler.Config(config); err != nil {
		return err
	}

	var vulns []*govulncheck.Vuln
	switch cfg.mode {
	case modeSource:
		dir := filepath.FromSlash(cfg.dir)
		vulns, err = runSource(ctx, handler, cfg, dir)
	case modeBinary:
		vulns, err = runBinary(ctx, handler, cfg)
	}
	if err != nil {
		return err
	}

	// For each vulnerability, queue it to be written to the output.
	for _, v := range vulns {
		if err := handler.Vulnerability(v); err != nil {
			return err
		}
	}
	if err := Flush(handler); err != nil {
		return err
	}
	if containsAffectedVulnerabilities(vulns) && !cfg.json {
		return ErrVulnerabilitiesFound
	}
	return nil
}

func containsAffectedVulnerabilities(vulns []*govulncheck.Vuln) bool {
	for _, v := range vulns {
		if IsCalled(v) {
			return true
		}
	}
	return false
}

func newConfig(ctx context.Context, cfg *config) *govulncheck.Config {
	config := govulncheck.Config{DataSource: cfg.db}
	if cfg.mode == modeSource {
		// The Go version is only relevant for source analysis, so omit it for
		// binary mode.
		if v, err := internal.GoEnv("GOVERSION"); err == nil {
			config.GoVersion = v
		}
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		config.Version = scannerVersion(bi)
	}
	if mod, err := cfg.Client.LastModifiedTime(ctx); err == nil {
		config.LastModified = &mod
	}
	return &config
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
	// TODO(https://go.dev/issue/29228): we manually change this after every
	// minor revision? bi.Main.Version does not seem to work.
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
