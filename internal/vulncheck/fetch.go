// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"context"

	"golang.org/x/vuln/internal/client"
)

// FetchVulnerabilities fetches vulnerabilities that affect the supplied modules.
func FetchVulnerabilities(ctx context.Context, client client.Client, modules []*Module) ([]*ModVulns, error) {
	var mv []*ModVulns
	for _, mod := range modules {
		modPath := mod.Path
		if mod.Replace != nil {
			modPath = mod.Replace.Path
		}
		vulns, err := client.ByModule(ctx, modPath)
		if err != nil {
			return nil, err
		}
		if len(vulns) == 0 {
			continue
		}
		mv = append(mv, &ModVulns{
			Module: mod,
			Vulns:  vulns,
		})
	}
	return mv, nil
}
