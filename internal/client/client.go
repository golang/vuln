// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package client provides an interface for accessing vulnerability
// databases, via either HTTP or local filesystem access.
//
// The protocol is described at https://go.dev/security/vuln/database.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/osv"
	isem "golang.org/x/vuln/internal/semver"
	"golang.org/x/vuln/internal/web"
)

// A Client for reading vulnerability databases.
type Client struct {
	source
}

type Options struct {
	HTTPClient *http.Client
}

// NewClient returns a client that reads the vulnerability database
// in source (an "http" or "file" prefixed URL).
//
// It supports databases following the API described
// in https://go.dev/security/vuln/database#api.
func NewClient(source string, opts *Options) (_ *Client, err error) {
	source = strings.TrimRight(source, "/")
	uri, err := url.Parse(source)
	if err != nil {
		return nil, err
	}
	switch uri.Scheme {
	case "http", "https":
		return newHTTPClient(uri, opts)
	case "file":
		return newLocalClient(uri)
	default:
		return nil, fmt.Errorf("source %q has unsupported scheme", uri)
	}
}

var errLegacyUnsupported = fmt.Errorf("the legacy vulndb schema is no longer supported; see https://go.dev/security/vuln/database#api for the new schema")

func newHTTPClient(uri *url.URL, opts *Options) (*Client, error) {
	// v1 returns true if the given source likely follows the V1 schema.
	// This is always true if the source is "https://vuln.go.dev".
	// Otherwise, this is determined by checking if the "index/db.json.gz"
	// endpoint is present.
	v1 := func() bool {
		source := uri.String()
		if source == "https://vuln.go.dev" {
			return true
		}
		r, err := http.Head(source + "/index/db.json.gz")
		if err != nil || r.StatusCode != http.StatusOK {
			return false
		}
		return true
	}
	if !v1() {
		return nil, errLegacyUnsupported
	}
	return &Client{source: newHTTPSource(uri.String(), opts)}, nil
}

func newLocalClient(uri *url.URL) (*Client, error) {
	// v1 returns true if the given source likely follows the
	// v1 schema. This is determined by checking if the "index/db.json"
	// endpoint is present.
	v1 := func() bool {
		dir, err := web.URLToFilePath(uri)
		if err != nil {
			return false
		}
		_, err = os.Stat(filepath.Join(dir, dbEndpoint+".json"))
		return err == nil
	}
	if !v1() {
		return nil, errLegacyUnsupported
	}
	fs, err := newLocalSource(uri)
	if err != nil {
		return nil, err
	}
	return &Client{source: fs}, nil
}

func NewInMemoryClient(entries []*osv.Entry) (*Client, error) {
	s, err := newInMemorySource(entries)
	if err != nil {
		return nil, err
	}
	return &Client{source: s}, nil
}

func (c *Client) LastModifiedTime(ctx context.Context) (_ time.Time, err error) {
	derrors.Wrap(&err, "LastModifiedTime()")

	b, err := c.source.get(ctx, dbEndpoint)
	if err != nil {
		return time.Time{}, err
	}

	var dbMeta dbMeta
	if err := json.Unmarshal(b, &dbMeta); err != nil {
		return time.Time{}, err
	}

	return dbMeta.Modified, nil
}

type ModuleRequest struct {
	// The module path to filter on.
	// This must be set (if empty, ByModule errors).
	Path string
	// (Optional) If set, only return vulnerabilities affected
	// at this version.
	Version string
}

// ByModule returns the OSV entries matching the ModuleRequest,
// or (nil, nil) if there are none.
func (c *Client) ByModule(ctx context.Context, req ModuleRequest) (_ []*osv.Entry, err error) {
	derrors.Wrap(&err, "ByModule(%v)", req)

	if req.Path == "" {
		return nil, fmt.Errorf("module path must be set")
	}

	if req.Version != "" && !isem.Valid(req.Version) {
		return nil, fmt.Errorf("version %s is not valid semver", req.Version)
	}

	b, err := c.source.get(ctx, modulesEndpoint)
	if err != nil {
		return nil, err
	}

	dec, err := newStreamDecoder(b)
	if err != nil {
		return nil, err
	}

	var ids []string
	for dec.More() {
		var m moduleMeta
		err := dec.Decode(&m)
		if err != nil {
			return nil, err
		}
		if m.Path == req.Path {
			for _, v := range m.Vulns {
				if v.Fixed == "" || isem.Less(req.Version, v.Fixed) {
					ids = append(ids, v.ID)
				}
			}
			// We found the requested module, so skip the rest.
			break
		}
	}

	if len(ids) == 0 {
		return nil, nil
	}

	entries, err := c.byIDs(ctx, ids)
	if err != nil {
		return nil, err
	}

	// Filter by version.
	if req.Version != "" {
		affected := func(e *osv.Entry) bool {
			for _, a := range e.Affected {
				if a.Module.Path == req.Path && isem.Affects(a.Ranges, req.Version) {
					return true
				}
			}
			return false
		}

		var filtered []*osv.Entry
		for _, entry := range entries {
			if affected(entry) {
				filtered = append(filtered, entry)
			}
		}
		if len(filtered) == 0 {
			return nil, nil
		}
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].ID < entries[j].ID
	})

	return entries, nil
}

func (c *Client) byIDs(ctx context.Context, ids []string) (_ []*osv.Entry, err error) {
	entries := make([]*osv.Entry, len(ids))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(10)
	for i, id := range ids {
		i, id := i, id
		g.Go(func() error {
			e, err := c.byID(gctx, id)
			if err != nil {
				return err
			}
			entries[i] = e
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	return entries, nil
}

// byID returns the OSV entry with the given ID,
// or an error if it does not exist / cannot be unmarshaled.
func (c *Client) byID(ctx context.Context, id string) (_ *osv.Entry, err error) {
	derrors.Wrap(&err, "byID(%s)", id)

	b, err := c.source.get(ctx, entryEndpoint(id))
	if err != nil {
		return nil, err
	}

	var entry osv.Entry
	if err := json.Unmarshal(b, &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}

// newStreamDecoder returns a decoder that can be used
// to read an array of JSON objects.
func newStreamDecoder(b []byte) (*json.Decoder, error) {
	dec := json.NewDecoder(bytes.NewBuffer(b))

	// skip open bracket
	_, err := dec.Token()
	if err != nil {
		return nil, err
	}

	return dec, nil
}
