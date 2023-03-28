// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package client provides an interface for accessing vulnerability
// databases, via either HTTP or local filesystem access.
//
// The protocol is described at https://go.dev/security/vulndb/#protocol.
//
// The expected database layout is the same for both HTTP and local
// databases. The database index is located at the root of the
// database, and contains a list of all of the vulnerable modules
// documented in the database and the time the most recent vulnerability
// was added. The index file is called index.json, and has the
// following format:
//
//	map[string]time.Time (DBIndex)
//
// Each vulnerable module is represented by an individual JSON file
// which contains all of the vulnerabilities in that module. The path
// for each module file is simply the import path of the module.
// For example, vulnerabilities in golang.org/x/crypto are contained in the
// golang.org/x/crypto.json file. The per-module JSON files contain a slice of
// https://pkg.go.dev/golang.org/x/vuln/internal/osv#Entry.
//
// A single client.Client can be used to access multiple vulnerability
// databases. When looking up vulnerable modules, each database is
// consulted, and results are merged together.
package client

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/osv"
)

// DBIndex contains a mapping of vulnerable packages to the last time a new
// vulnerability was added to the database.
type DBIndex map[string]time.Time

// Client interface for fetching vulnerabilities based on module path or ID.
type Client interface {
	// GetByModule returns the entries that affect the given module path.
	// It returns (nil, nil) if there are none.
	GetByModule(context.Context, string) ([]*osv.Entry, error)

	// GetByID returns the entry with the given ID, or (nil, nil) if there isn't
	// one.
	GetByID(context.Context, string) (*osv.Entry, error)

	// GetByAlias returns the entries that have the given aliases, or (nil, nil)
	// if there are none.
	GetByAlias(context.Context, string) ([]*osv.Entry, error)

	// ListIDs returns the IDs of all entries in the database.
	ListIDs(context.Context) ([]string, error)

	// LastModifiedTime returns the time that the database was last modified.
	// It can be used by tools that periodically check for vulnerabilities
	// to avoid repeating work.
	LastModifiedTime(context.Context) (time.Time, error)
}

func getByIDs(ctx context.Context, client Client, ids []string) ([]*osv.Entry, error) {
	var entries []*osv.Entry
	for _, id := range ids {
		e, err := client.GetByID(ctx, id)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// Pseudo-module paths used for parts of the Go system.
// These are technically not valid module paths, so we
// mustn't pass them to module.EscapePath.
// Keep in sync with vulndb/internal/database/generate.go.
var specialCaseModulePaths = map[string]bool{
	internal.GoStdModulePath: true,
	internal.GoCmdModulePath: true,
}

// EscapeModulePath should be called by cache implementations or other users of
// this package that want to use module paths as filesystem paths. It is like
// golang.org/x/mod/module, but accounts for special paths used by the
// vulnerability database.
func EscapeModulePath(path string) (string, error) {
	if specialCaseModulePaths[path] {
		return path, nil
	}
	return module.EscapePath(path)
}

// UnescapeModulePath should be called to convert filesystem paths into module
// paths. It is like golang.org/x/mod/module, but accounts for special paths
// used by the vulnerability database.
func UnescapeModulePath(path string) (string, error) {
	if specialCaseModulePaths[path] {
		return path, nil
	}
	return module.UnescapePath(path)
}

func latestModifiedTime(entries []*osv.Entry) time.Time {
	var t time.Time
	for _, e := range entries {
		if e.Modified.After(t) {
			t = e.Modified
		}
	}
	return t
}

func NewClient(source string, opts Options) (_ Client, err error) {
	source = strings.TrimRight(source, "/")
	uri, err := url.Parse(source)
	if err != nil {
		return nil, err
	}
	switch uri.Scheme {
	case "http", "https":
		return newHTTPClient(uri, opts), nil
	case "file":
		return newFileClient(uri)
	default:
		return nil, fmt.Errorf("source %q has unsupported scheme", uri)
	}
}
