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
	"golang.org/x/vuln/internal/web"
)

// Client interface for fetching vulnerabilities based on module path or ID.
type Client interface {
	// ByModule returns the entries that affect the given module path.
	// It returns (nil, nil) if there are none.
	ByModule(context.Context, string) ([]*osv.Entry, error)

	// LastModifiedTime returns the time that the database was last modified.
	// It can be used by tools that periodically check for vulnerabilities
	// to avoid repeating work.
	LastModifiedTime(context.Context) (time.Time, error)
}

// NewClient returns a client that reads the vulnerability database
// in source (an "http" or "file" prefixed URL).
//
// It currently supports database sources in both the v1 and legacy
// formats, preferring the v1 format if both are implemented.
// Support for the legacy database format will be removed soon.
func NewClient(source string, opts *Options) (_ Client, err error) {
	source = strings.TrimRight(source, "/")
	uri, err := url.Parse(source)
	if err != nil {
		return nil, err
	}
	switch uri.Scheme {
	case "http", "https":
		return newHTTPClient(uri, opts), nil
	case "file":
		return newLocalClient(uri)
	default:
		return nil, fmt.Errorf("source %q has unsupported scheme", uri)
	}
}

func newHTTPClient(uri *url.URL, opts *Options) Client {
	// v1 returns true if the given source likely follows the V1 schema.
	// This is always true if the source is "https://vuln.go.dev".
	// Otherwise, this is determined by checking if the "index/db.json"
	// endpoint is present.
	v1 := func() bool {
		source := uri.String()
		if source == "https://vuln.go.dev" {
			return true
		}
		r, err := http.Head(source + "/index/db.json")
		if err != nil || r.StatusCode != http.StatusOK {
			return false
		}
		return true
	}
	if v1() {
		return newHTTPClientV1(uri, opts)
	}
	return newLegacyHTTPClient(uri, opts)
}

func newLocalClient(uri *url.URL) (Client, error) {
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
	if v1() {
		return newLocalClientV1(uri)
	}
	return newLegacyLocalClient(uri)
}

func NewV1Client(source string, opts *Options) (_ Client, err error) {
	source = strings.TrimRight(source, "/")
	uri, err := url.Parse(source)
	if err != nil {
		return nil, err
	}
	switch uri.Scheme {
	case "http", "https":
		return newHTTPClientV1(uri, opts), nil
	case "file":
		return newLocalClientV1(uri)
	default:
		return nil, fmt.Errorf("source %q has unsupported scheme", uri)
	}
}

func NewInMemoryClient(entries []*osv.Entry) (Client, error) {
	s, err := newInMemorySource(entries)
	if err != nil {
		return nil, err
	}
	return &client{source: s}, nil
}

// A client for reading v1 vulnerability databases.
type client struct {
	source
}

func newHTTPClientV1(uri *url.URL, opts *Options) *client {
	return &client{source: newHTTPSource(uri.String(), opts)}
}

func newLocalClientV1(uri *url.URL) (*client, error) {
	fs, err := newLocalSource(uri)
	if err != nil {
		return nil, err
	}
	return &client{source: fs}, nil
}

func (c *client) LastModifiedTime(ctx context.Context) (_ time.Time, err error) {
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

// ByModule returns the OSV entries matching the module request.
func (c *client) ByModule(ctx context.Context, modulePath string) (_ []*osv.Entry, err error) {
	derrors.Wrap(&err, "ByModule(%v)", modulePath)

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
		if m.Path == modulePath {
			for _, v := range m.Vulns {
				ids = append(ids, v.ID)
			}
			// We found the requested module, so skip the rest.
			break
		}
	}

	if len(ids) == 0 {
		return nil, nil
	}

	// Fetch all the entries in parallel.
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(10)
	entries := make([]*osv.Entry, len(ids))
	for i, id := range ids {
		i := i
		id := id
		g.Go(func() error {
			entry, err := c.byID(gctx, id)
			if err != nil {
				return err
			}

			entries[i] = entry

			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].ID < entries[j].ID
	})

	return entries, nil
}

// byID returns the OSV entry with the given ID,
// or an error if it does not exist / cannot be unmarshaled.
func (c *client) byID(ctx context.Context, id string) (_ *osv.Entry, err error) {
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
