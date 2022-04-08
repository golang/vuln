// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package client provides an interface for accessing vulnerability
// databases, via either HTTP or local filesystem access.
//
// The expected database layout is the same for both HTTP and local
// databases. The database  index is located at the root of the
// database, and contains a list of all of the vulnerable modules
// documented in the databse and the time the most recent vulnerability
// was added. The index file is called indx.json, and has the
// following format:
//
//	map[string]time.Time (DBIndex)
//
// Each vulnerable module is represented by an individual JSON file
// which contains all of the vulnerabilities in that module. The path
// for each module file is simply the import path of the module,
// i.e. vulnerabilities in golang.org/x/crypto are contained in the
// golang.org/x/crypto.json file. The per-module JSON files have
// the following format:
//
//	[]osv.Entry
//
// A single client.Client can be used to access multiple vulnerability
// databases. When looking up vulnerable module each database is
// consulted, and results are merged together.
//
// TODO: allow filtering private module, possibly at a database level?
// (e.g. I may want to use multiple databases, but only lookup a specific
// module in a subset of them)
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/osv"
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

	// ListIDs returns the IDs of all entries in the database.
	ListIDs(context.Context) ([]string, error)

	// LastModifiedTime returns the time that the database was last modified.
	// It can be used by tools that periodically check for vulnerabilities
	// to avoid repeating work.
	LastModifiedTime(context.Context) (time.Time, error)

	unexported() // ensures that adding a method won't break users
}

type source interface {
	Client
	Index(context.Context) (DBIndex, error)
}

type localSource struct {
	dir string
}

func (*localSource) unexported() {}

func (ls *localSource) GetByModule(_ context.Context, module string) (_ []*osv.Entry, err error) {
	defer derrors.Wrap(&err, "GetByModule(%q)", module)
	content, err := ioutil.ReadFile(filepath.Join(ls.dir, module+".json"))
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var e []*osv.Entry
	if err = json.Unmarshal(content, &e); err != nil {
		return nil, err
	}
	return e, nil
}

func (ls *localSource) GetByID(_ context.Context, id string) (_ *osv.Entry, err error) {
	defer derrors.Wrap(&err, "GetByID(%q)", id)
	content, err := ioutil.ReadFile(filepath.Join(ls.dir, internal.IDDirectory, id+".json"))
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var e osv.Entry
	if err = json.Unmarshal(content, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func (ls *localSource) ListIDs(context.Context) (_ []string, err error) {
	defer derrors.Wrap(&err, "ListIDs()")
	content, err := ioutil.ReadFile(filepath.Join(ls.dir, internal.IDDirectory, "index.json"))
	if err != nil {
		return nil, err
	}
	var ids []string
	if err := json.Unmarshal(content, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

func (ls *localSource) LastModifiedTime(context.Context) (_ time.Time, err error) {
	defer derrors.Wrap(&err, "LastModifiedTime()")

	// Assume that if anything changes, the index does.
	info, err := os.Stat(filepath.Join(ls.dir, "index.json"))
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

func (ls *localSource) Index(context.Context) (_ DBIndex, err error) {
	defer derrors.Wrap(&err, "Index()")
	var index DBIndex
	b, err := ioutil.ReadFile(filepath.Join(ls.dir, "index.json"))
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &index); err != nil {
		return nil, err
	}
	return index, nil
}

type httpSource struct {
	url    string // the base URI of the source (without trailing "/"). e.g. https://vuln.golang.org
	c      *http.Client
	cache  Cache
	dbName string
}

func (hs *httpSource) Index(ctx context.Context) (_ DBIndex, err error) {
	defer derrors.Wrap(&err, "Index()")

	var cachedIndex DBIndex
	var cachedIndexRetrieved *time.Time

	if hs.cache != nil {
		index, retrieved, err := hs.cache.ReadIndex(hs.dbName)
		if err != nil {
			return nil, err
		}

		cachedIndex = index
		if cachedIndex != nil {
			if time.Since(retrieved) < time.Hour*2 {
				return cachedIndex, nil
			}

			cachedIndexRetrieved = &retrieved
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/index.json", hs.url), nil)
	if err != nil {
		return nil, err
	}
	if cachedIndexRetrieved != nil {
		req.Header.Add("If-Modified-Since", cachedIndexRetrieved.Format(http.TimeFormat))
	}
	resp, err := hs.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if cachedIndexRetrieved != nil && resp.StatusCode == http.StatusNotModified {
		// If status has not been modified, this is equivalent to returning the
		// same index. We update the timestamp so the next cache index read does
		// not require a roundtrip to the server.
		if err = hs.cache.WriteIndex(hs.dbName, cachedIndex, time.Now()); err != nil {
			return nil, err
		}
		return cachedIndex, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var index DBIndex
	if err = json.Unmarshal(b, &index); err != nil {
		return nil, err
	}

	if hs.cache != nil {
		if err = hs.cache.WriteIndex(hs.dbName, index, time.Now()); err != nil {
			return nil, err
		}
	}

	return index, nil
}

func (*httpSource) unexported() {}

func (hs *httpSource) GetByModule(ctx context.Context, module string) (_ []*osv.Entry, err error) {
	defer derrors.Wrap(&err, "GetByModule(%q)", module)

	index, err := hs.Index(ctx)
	if err != nil {
		return nil, err
	}

	lastModified, present := index[module]
	if !present {
		return nil, nil
	}

	if hs.cache != nil {
		if cached, err := hs.cache.ReadEntries(hs.dbName, module); err != nil {
			return nil, err
		} else if len(cached) != 0 {
			var stale bool
			for _, c := range cached {
				if c.Modified.Before(lastModified) {
					stale = true
					break
				}
			}
			if !stale {
				return cached, nil
			}
		}
	}

	content, err := hs.readBody(ctx, fmt.Sprintf("%s/%s.json", hs.url, module))
	if err != nil || content == nil {
		return nil, err
	}
	var e []*osv.Entry
	// TODO: we may want to check that the returned entries actually match
	// the module we asked about, so that the cache cannot be poisoned
	if err = json.Unmarshal(content, &e); err != nil {
		return nil, err
	}

	if hs.cache != nil {
		if err := hs.cache.WriteEntries(hs.dbName, module, e); err != nil {
			return nil, err
		}
	}
	return e, nil
}

func (hs *httpSource) GetByID(ctx context.Context, id string) (_ *osv.Entry, err error) {
	defer derrors.Wrap(&err, "GetByID(%q)", id)

	content, err := hs.readBody(ctx, fmt.Sprintf("%s/%s/%s.json", hs.url, internal.IDDirectory, id))
	if err != nil || content == nil {
		return nil, err
	}
	var e osv.Entry
	if err := json.Unmarshal(content, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func (hs *httpSource) ListIDs(ctx context.Context) (_ []string, err error) {
	defer derrors.Wrap(&err, "ListIDs()")

	content, err := hs.readBody(ctx, fmt.Sprintf("%s/%s/index.json", hs.url, internal.IDDirectory))
	if err != nil {
		return nil, err
	}
	var ids []string
	if err := json.Unmarshal(content, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// This is the format for the last-modified header, as described at
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Last-Modified.
var lastModifiedFormat = "Mon, 2 Jan 2006 15:04:05 GMT"

func (hs *httpSource) LastModifiedTime(ctx context.Context) (_ time.Time, err error) {
	defer derrors.Wrap(&err, "LastModifiedTime()")

	// Assume that if anything changes, the index does.
	url := fmt.Sprintf("%s/index.json", hs.url)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return time.Time{}, err
	}
	resp, err := hs.c.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	if resp.StatusCode != 200 {
		return time.Time{}, fmt.Errorf("got status code %d", resp.StatusCode)
	}
	h := resp.Header.Get("Last-Modified")
	return time.Parse(lastModifiedFormat, h)
}

func (hs *httpSource) readBody(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hs.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	// might want this to be a LimitedReader
	return ioutil.ReadAll(resp.Body)
}

type client struct {
	sources []source
}

type Options struct {
	HTTPClient *http.Client
	HTTPCache  Cache
}

func NewClient(sources []string, opts Options) (_ Client, err error) {
	defer derrors.Wrap(&err, "NewClient(%v, opts)", sources)
	c := &client{}
	for _, uri := range sources {
		uri = strings.TrimRight(uri, "/")
		// should parse the URI out here instead of in there
		switch {
		case strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://"):
			hs := &httpSource{url: uri}
			url, err := url.Parse(uri)
			if err != nil {
				return nil, err
			}
			hs.dbName = url.Hostname()
			if opts.HTTPCache != nil {
				hs.cache = opts.HTTPCache
			}
			if opts.HTTPClient != nil {
				hs.c = opts.HTTPClient
			} else {
				hs.c = new(http.Client)
			}
			c.sources = append(c.sources, hs)
		case strings.HasPrefix(uri, "file://"):
			dir := strings.TrimPrefix(uri, "file://")
			fi, err := os.Stat(dir)
			if err != nil {
				return nil, err
			}
			if !fi.IsDir() {
				return nil, fmt.Errorf("%s is not a directory", dir)
			}
			c.sources = append(c.sources, &localSource{dir: dir})
		default:
			return nil, fmt.Errorf("source %q has unsupported scheme", uri)
		}
	}
	return c, nil
}

func (*client) unexported() {}

func (c *client) GetByModule(ctx context.Context, module string) (_ []*osv.Entry, err error) {
	defer derrors.Wrap(&err, "GetByModule(%q)", module)
	var entries []*osv.Entry
	// probably should be parallelized
	for _, s := range c.sources {
		e, err := s.GetByModule(ctx, module)
		if err != nil {
			return nil, err // be failure tolerant?
		}
		entries = append(entries, e...)
	}
	return entries, nil
}

func (c *client) GetByID(ctx context.Context, id string) (_ *osv.Entry, err error) {
	defer derrors.Wrap(&err, "GetByID(%q)", id)
	for _, s := range c.sources {
		entry, err := s.GetByID(ctx, id)
		if err != nil {
			return nil, err // be failure tolerant?
		}
		if entry != nil {
			return entry, nil
		}
	}
	return nil, nil
}

// ListIDs returns the union of the IDs from all sources,
// sorted lexically.
func (c *client) ListIDs(ctx context.Context) (_ []string, err error) {
	defer derrors.Wrap(&err, "ListIDs()")
	idSet := map[string]bool{}
	for _, s := range c.sources {
		ids, err := s.ListIDs(ctx)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			idSet[id] = true
		}
	}
	var ids []string
	for id := range idSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// LastModifiedTime returns the latest modified time of all the sources.
func (c *client) LastModifiedTime(ctx context.Context) (_ time.Time, err error) {
	defer derrors.Wrap(&err, "LastModifiedTime()")
	var lmt time.Time
	for _, s := range c.sources {
		t, err := s.LastModifiedTime(ctx)
		if err != nil {
			return time.Time{}, err
		}
		if t.After(lmt) {
			lmt = t
		}
	}
	return lmt, nil
}
