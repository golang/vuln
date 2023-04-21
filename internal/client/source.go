// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"sort"

	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/osv"
	isem "golang.org/x/vuln/internal/semver"
	"golang.org/x/vuln/internal/web"
)

type source interface {
	// get returns the raw, uncompressed bytes at the
	// requested endpoint, which should be bare with no file extensions
	// (e.g., "index/modules" instead of "index/modules.json.gz").
	// It errors if the endpoint cannot be reached or does not exist
	// in the expected form.
	get(ctx context.Context, endpoint string) ([]byte, error)
}

func newHTTPSource(url string, opts *Options) *httpSource {
	c := http.DefaultClient
	if opts != nil && opts.HTTPClient != nil {
		c = opts.HTTPClient
	}
	return &httpSource{url: url, c: c}
}

// httpSource reads a vulnerability database from an http(s) source.
type httpSource struct {
	url string
	c   *http.Client
}

func (hs *httpSource) get(ctx context.Context, endpoint string) (_ []byte, err error) {
	derrors.Wrap(&err, "get(%s)", endpoint)

	reqURL := fmt.Sprintf("%s/%s", hs.url, endpoint+".json.gz")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hs.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status code: %d", resp.StatusCode)
	}

	// Uncompress the result.
	r, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	return io.ReadAll(r)
}

func newLocalSource(u *url.URL) (*localSource, error) {
	dir, err := web.URLToFilePath(u)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	return &localSource{fs: os.DirFS(dir)}, nil
}

// localSource reads a vulnerability database from a local file system.
type localSource struct {
	fs fs.FS
}

func (ls *localSource) get(ctx context.Context, endpoint string) (_ []byte, err error) {
	derrors.Wrap(&err, "get(%s)", endpoint)

	return fs.ReadFile(ls.fs, endpoint+".json")
}

// newInMemorySource creates a new in-memory source.
// Adapted from x/vulndb/internal/database.go.
func newInMemorySource(entries []*osv.Entry) (*inMemorySource, error) {
	data := make(map[string][]byte)
	db := dbMeta{}
	modulesMap := make(map[string]*moduleMeta)
	for _, entry := range entries {
		if entry.ID == "" {
			return nil, fmt.Errorf("entry %v has no ID", entry)
		}
		if entry.Modified.After(db.Modified) {
			db.Modified = entry.Modified
		}
		for _, affected := range entry.Affected {
			modulePath := affected.Module.Path
			if _, ok := modulesMap[modulePath]; !ok {
				modulesMap[modulePath] = &moduleMeta{
					Path:  modulePath,
					Vulns: []moduleVuln{},
				}
			}
			module := modulesMap[modulePath]
			module.Vulns = append(module.Vulns, moduleVuln{
				ID:       entry.ID,
				Modified: entry.Modified,
				Fixed:    latestFixedVersion(affected.Ranges),
			})
		}
		b, err := json.Marshal(entry)
		if err != nil {
			return nil, err
		}
		data[entryEndpoint(entry.ID)] = b
	}

	b, err := json.Marshal(db)
	if err != nil {
		return nil, err
	}
	data[dbEndpoint] = b

	// Add the modules endpoint.
	modules := make([]*moduleMeta, 0, len(modulesMap))
	for _, module := range modulesMap {
		modules = append(modules, module)
	}
	sort.SliceStable(modules, func(i, j int) bool {
		return modules[i].Path < modules[j].Path
	})
	for _, module := range modules {
		sort.SliceStable(module.Vulns, func(i, j int) bool {
			return module.Vulns[i].ID < module.Vulns[j].ID
		})
	}
	b, err = json.Marshal(modules)
	if err != nil {
		return nil, err
	}
	data[modulesEndpoint] = b

	return &inMemorySource{data: data}, nil
}

// inMemorySource reads databases from an in-memory map.
// Currently intended for use only in unit tests.
type inMemorySource struct {
	data map[string][]byte
}

func (db *inMemorySource) get(ctx context.Context, endpoint string) ([]byte, error) {
	b, ok := db.data[endpoint]
	if !ok {
		return nil, fmt.Errorf("no data found at endpoint %q", endpoint)
	}
	return b, nil
}

func latestFixedVersion(ranges []osv.Range) string {
	var latestFixed string
	for _, r := range ranges {
		if r.Type == "SEMVER" {
			for _, e := range r.Events {
				fixed := e.Fixed
				if fixed != "" && isem.Less(latestFixed, fixed) {
					latestFixed = fixed
				}
			}
			// If the vulnerability was re-introduced after the latest fix
			// we found, there is no latest fix for this range.
			for _, e := range r.Events {
				introduced := e.Introduced
				if introduced != "" && introduced != "0" && isem.Less(latestFixed, introduced) {
					latestFixed = ""
					break
				}
			}
		}
	}
	return latestFixed
}
