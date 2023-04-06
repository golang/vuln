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
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/osv"
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

func NewClient(source string, opts *Options) (_ Client, err error) {
	source = strings.TrimRight(source, "/")
	uri, err := url.Parse(source)
	if err != nil {
		return nil, err
	}
	switch uri.Scheme {
	case "http", "https":
		return &client{source: newHTTPSource(uri.String(), opts)}, nil
	case "file":
		fs, err := newLocalSource(uri)
		if err != nil {
			return nil, err
		}
		return &client{source: fs}, nil
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

type client struct {
	source
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

// ByPackage returns the OSV entries matching the package request.
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
