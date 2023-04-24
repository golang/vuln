// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"context"
	"fmt"
	"regexp"

	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/govulncheck"
	isem "golang.org/x/vuln/internal/semver"
)

// runQuery reports vulnerabilities that apply to the given query.
func runQuery(ctx context.Context, handler govulncheck.Handler, cfg *config, c *client.Client) ([]*govulncheck.Vuln, error) {
	mod, ver, err := parseModuleQuery(cfg.patterns[0])
	if err != nil {
		return nil, err
	}

	if err := handler.Progress(queryProgressMessage(mod, ver)); err != nil {
		return nil, err
	}

	resp, err := c.ByModules(ctx, []*client.ModuleRequest{{
		Path: mod, Version: ver,
	}})
	if err != nil {
		return nil, err
	}
	// This will never happen unless there is a bug in ByModules,
	// because it always returns one response per request.
	if len(resp) != 1 {
		return nil, fmt.Errorf("internal error: could not fetch vulnerabilities for %s@%s", mod, ver)
	}

	entries := resp[0].Entries
	if len(entries) == 0 {
		return nil, nil
	}

	vulns := make([]*govulncheck.Vuln, len(entries))
	for i, entry := range entries {
		vulns[i] = &govulncheck.Vuln{
			OSV: entry,
			// Modules not set in query mode.
		}
	}

	return vulns, nil
}

func queryProgressMessage(module, version string) *govulncheck.Progress {
	return &govulncheck.Progress{
		Message: fmt.Sprintf("Looking up vulnerabilities in %s at %s...", module, version),
	}
}

var modQueryRegex = regexp.MustCompile(`(.+)@(.+)`)

func parseModuleQuery(pattern string) (_ string, _ string, err error) {
	matches := modQueryRegex.FindStringSubmatch(pattern)
	// matches should be [module@version, module, version]
	if len(matches) != 3 {
		return "", "", fmt.Errorf("invalid query %s: must be of the form module@version", pattern)
	}
	mod, ver := matches[1], matches[2]
	if !isem.Valid(ver) {
		return "", "", fmt.Errorf("version %s is not valid semver", ver)
	}

	return mod, ver, nil
}
