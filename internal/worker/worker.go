// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package worker is used to fetch and create issues for CVEs that are
// potential Go vulnerabilities.
package worker

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/vuln/internal/cveschema"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/report"
)

// Run clones the CVEProject/cvelist repository and compares the files to the
// existing triaged-cve-list.
func Run(dirpath string, triaged map[string]string) (err error) {
	defer derrors.Wrap(&err, "Run(triaged)")
	var repo *git.Repository
	if dirpath != "" {
		repo, err = openRepo(dirpath)
	} else {
		repo, err = cloneRepo(cvelistRepoURL)
	}
	if err != nil {
		return err
	}
	root, err := getRepoRoot(repo)
	if err != nil {
		return err
	}
	t := newTriager(triaged)
	log.Printf("Finding new Go vulnerabilities from CVE list...")
	if err := walkRepo(repo, root, "", t); err != nil {
		return err
	}
	for cveID, r := range t {
		if r.isGoVuln {
			fmt.Println(cveID)
		}
	}
	log.Printf("Found %d new issues from %d CVEs", t.totalVulns(), t.totalCVEs())
	return nil
}

// walkRepo looks at the files in t, recursively, and check if it is a CVE that
// needs to be manually triaged.
func walkRepo(repo *git.Repository, root *object.Tree, dirpath string, t triager) (err error) {
	defer derrors.Wrap(&err, "walkRepo(repo, root, %q, t)", dirpath)
	for _, e := range root.Entries {
		fp := path.Join(dirpath, e.Name)
		if !strings.HasPrefix(fp, "202") {
			continue
		}
		switch e.Mode {
		case filemode.Dir:
			root2, err := repo.TreeObject(e.Hash)
			if err != nil {
				return err
			}
			if err := walkRepo(repo, root2, fp, t); err != nil {
				return err
			}
		default:
			if !strings.HasPrefix(e.Name, "CVE-") {
				continue
			}
			cveID := strings.TrimSuffix(e.Name, ".json")
			if t.contains(cveID) {
				continue
			}
			c, err := parseCVE(repo, e)
			if err != nil {
				return err
			}
			issue, err := cveToIssue(c)
			if err != nil {
				return err
			}
			if issue != nil {
				t.add(issue)
			}
		}
	}
	return nil
}

// parseCVEJSON parses a CVE file following the CVE JSON format:
// https://github.com/CVEProject/automation-working-group/blob/master/cve_json_schema/DRAFT-JSON-file-format-v4.md
func parseCVE(r *git.Repository, e object.TreeEntry) (_ *cveschema.CVE, err error) {
	defer derrors.Wrap(&err, "parseCVE(r, e)")
	blob, err := r.BlobObject(e.Hash)
	if err != nil {
		return nil, fmt.Errorf("r.BlobObject: %v", err)
	}
	src, err := blob.Reader()
	if err != nil {
		return nil, fmt.Errorf("blob.Reader: %v", err)
	}
	defer func() {
		cerr := src.Close()
		if err == nil {
			err = cerr
		}
	}()
	var c cveschema.CVE
	d := json.NewDecoder(src)
	if err := d.Decode(&c); err != nil {
		return nil, fmt.Errorf("d.Decode: %v", err)
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

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
