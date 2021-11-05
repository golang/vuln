// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/vuln/internal/cveschema"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/report"
)

const goGitHubRepo = "github.com/golang/go"

// cveToIssue creates a cveRecord from a c *cveschema.CVE.
func cveToIssue(c *cveschema.CVE) (_ *cve, err error) {
	defer derrors.Wrap(&err, "cveToIssue(%q)", c.CVEDataMeta.ID)
	if isPendingCVE(c) {
		return nil, nil
	}
	switch c.DataVersion {
	case "4.0":
		return cveToIssueV4(c)
	default:
		// TODO(https://golang.org/issue/49289): Add support for v5.0.
		log.Printf("Unxpected data_version for CVE %q: %q (skipping)", c.CVEDataMeta.ID, c.DataVersion)
		return nil, nil
	}
}

func cveToIssueV4(c *cveschema.CVE) (_ *cve, err error) {
	mp, err := modulePathFromCVE(c)
	if err != nil {
		return nil, err
	}
	if mp == "" {
		return nil, nil
	}
	var links report.Links
	for _, r := range c.References.ReferenceData {
		if links.Commit == "" && strings.Contains(r.URL, "/commit/") {
			links.Commit = r.URL
		} else if links.PR == "" && strings.Contains(r.URL, "/pull/") {
			links.PR = r.URL
		} else {
			links.Context = append(links.Context, r.URL)
		}
	}
	var cwe string
	for _, pt := range c.Problemtype.ProblemtypeData {
		for _, d := range pt.Description {
			if strings.Contains(d.Value, "CWE") {
				cwe = d.Value
			}
		}
	}
	r := &cve{
		CVE:         *c,
		cwe:         cwe,
		modulePath:  mp,
		links:       links,
		description: description(c),
	}
	if mp == goGitHubRepo {
		r.modulePath = "Standard Library"
	}
	return r, nil
}

// isPendingCVE reports if the CVE is still waiting on information and not
// ready to be triaged.
func isPendingCVE(c *cveschema.CVE) bool {
	return c.CVEDataMeta.STATE == cveschema.StateReserved
}

var vcsHostsWithThreeElementRepoName = map[string]bool{
	"bitbucket.org": true,
	"gitea.com":     true,
	"gitee.com":     true,
	"github.com":    true,
	"gitlab.com":    true,
	"golang.org":    true,
}

// modulePathFromCVE returns a Go module path for a CVE, if we can determine
// what it is.
func modulePathFromCVE(c *cveschema.CVE) (_ string, err error) {
	defer derrors.Wrap(&err, "modulePathFromCVE(c)")
	for _, r := range c.References.ReferenceData {
		if r.URL == "" {
			continue
		}
		for host := range vcsHostsWithThreeElementRepoName {
			if !strings.Contains(r.URL, host) {
				continue
			}
			refURL, err := url.Parse(r.URL)
			if err != nil {
				return "", fmt.Errorf("url.Parse(%q): %v", r.URL, err)
			}
			u := refURL.Host + refURL.Path
			parts := strings.Split(u, "/")
			if len(parts) < 3 {
				continue
			}
			mod := strings.Join(parts[0:3], "/")
			r, err := http.DefaultClient.Get(fmt.Sprintf("https://pkg.go.dev/%s", mod))
			if err != nil {
				return "", err
			}
			if r.StatusCode == http.StatusOK {
				return mod, nil
			}
		}
	}
	return "", nil
}

func description(c *cveschema.CVE) string {
	var ds []string
	for _, d := range c.Description.DescriptionData {
		ds = append(ds, d.Value)
	}
	return strings.Join(ds, "| \n ")
}
