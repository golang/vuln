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
// https://pkg.go.dev/golang.org/x/vuln/osv#Entry.
//
// A single client.Client can be used to access multiple vulnerability
// databases. When looking up vulnerable modules, each database is
// consulted, and results are merged together.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/web"
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

	// GetByAlias returns the entries that have the given aliases, or (nil, nil)
	// if there are none.
	GetByAlias(context.Context, string) ([]*osv.Entry, error)

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

func (ls *localSource) GetByModule(ctx context.Context, modulePath string) (_ []*osv.Entry, err error) {
	defer derrors.Wrap(&err, "localSource.GetByModule(%q)", modulePath)

	index, err := ls.Index(ctx)
	if err != nil {
		return nil, err
	}
	// Query index first to be consistent with the way httpSource.GetByModule works.
	// Prevents opening and stating files on disk that don't need to be touched. Also
	// solves #56179.
	if _, present := index[modulePath]; !present {
		return nil, nil
	}

	epath, err := EscapeModulePath(modulePath)
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(filepath.Join(ls.dir, epath+".json"))
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
	content, err := os.ReadFile(filepath.Join(ls.dir, internal.IDDirectory, id+".json"))
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

func (ls *localSource) GetByAlias(ctx context.Context, alias string) (entries []*osv.Entry, err error) {
	defer derrors.Wrap(&err, "localSource.GetByAlias(%q)", alias)

	aliasToIDs, err := localReadJSON[map[string][]string](ctx, ls, "aliases.json")
	if err != nil {
		return nil, err
	}
	ids := aliasToIDs[alias]
	if len(ids) == 0 {
		return nil, nil
	}
	return getByIDs(ctx, ls, ids)
}

func getByIDs(ctx context.Context, s source, ids []string) ([]*osv.Entry, error) {
	var entries []*osv.Entry
	for _, id := range ids {
		e, err := s.GetByID(ctx, id)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (ls *localSource) ListIDs(ctx context.Context) (_ []string, err error) {
	defer derrors.Wrap(&err, "ListIDs()")

	return localReadJSON[[]string](ctx, ls, filepath.Join(internal.IDDirectory, "index.json"))
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

func (ls *localSource) Index(ctx context.Context) (_ DBIndex, err error) {
	defer derrors.Wrap(&err, "Index()")

	return localReadJSON[DBIndex](ctx, ls, "index.json")
}

func localReadJSON[T any](_ context.Context, ls *localSource, relativePath string) (T, error) {
	var zero T
	content, err := os.ReadFile(filepath.Join(ls.dir, relativePath))
	if err != nil {
		return zero, err
	}
	var t T
	if err := json.Unmarshal(content, &t); err != nil {
		return zero, err
	}
	return t, nil
}

type httpSource struct {
	url    string // the base URI of the source (without trailing "/"). e.g. https://vuln.golang.org
	c      *http.Client
	cache  Cache
	dbName string

	// indexCalls counts the number of times Index()
	// method has been called. httpCalls counts the
	// number of times GetByModule makes an http request
	// to the vuln db for a module path. Used for testing
	// privacy properties of httpSource.
	indexCalls int
	httpCalls  int
}

func (hs *httpSource) Index(ctx context.Context) (_ DBIndex, err error) {
	hs.indexCalls++ // for testing privacy properties
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
	b, err := io.ReadAll(resp.Body)
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

func (hs *httpSource) GetByModule(ctx context.Context, modulePath string) (_ []*osv.Entry, err error) {
	defer derrors.Wrap(&err, "httpSource.GetByModule(%q)", modulePath)

	index, err := hs.Index(ctx)
	if err != nil {
		return nil, err
	}

	lastModified, present := index[modulePath]
	if !present {
		return nil, nil
	}

	if hs.cache != nil {
		cached, err := hs.cache.ReadEntries(hs.dbName, modulePath)
		if err != nil {
			return nil, err
		}
		if len(cached) > 0 && !latestModifiedTime(cached).Before(lastModified) {
			return cached, nil
		}
	}

	epath, err := EscapeModulePath(modulePath)
	if err != nil {
		return nil, err
	}
	hs.httpCalls++ // for testing privacy properties
	entries, err := httpReadJSON[[]*osv.Entry](ctx, hs, epath+".json")
	if err != nil || entries == nil {
		return nil, err
	}
	// TODO: we may want to check that the returned entries actually match
	// the module we asked about, so that the cache cannot be poisoned
	if hs.cache != nil {
		if err := hs.cache.WriteEntries(hs.dbName, modulePath, entries); err != nil {
			return nil, err
		}
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

func (hs *httpSource) GetByID(ctx context.Context, id string) (_ *osv.Entry, err error) {
	defer derrors.Wrap(&err, "GetByID(%q)", id)

	return httpReadJSON[*osv.Entry](ctx, hs, fmt.Sprintf("%s/%s.json", internal.IDDirectory, id))
}

func (hs *httpSource) GetByAlias(ctx context.Context, alias string) (entries []*osv.Entry, err error) {
	defer derrors.Wrap(&err, "httpSource.GetByAlias(%q)", alias)

	aliasToIDs, err := httpReadJSON[map[string][]string](ctx, hs, "aliases.json")
	if err != nil {
		return nil, err
	}
	ids := aliasToIDs[alias]
	if len(ids) == 0 {
		return nil, nil
	}
	return getByIDs(ctx, hs, ids)
}

func (hs *httpSource) ListIDs(ctx context.Context) (_ []string, err error) {
	defer derrors.Wrap(&err, "ListIDs()")

	return httpReadJSON[[]string](ctx, hs, path.Join(internal.IDDirectory, "index.json"))
}

func httpReadJSON[T any](ctx context.Context, hs *httpSource, relativePath string) (T, error) {
	var zero T
	content, err := hs.readBody(ctx, fmt.Sprintf("%s/%s", hs.url, relativePath))
	if err != nil {
		return zero, err
	}
	if len(content) == 0 {
		return zero, nil
	}
	var t T
	if err := json.Unmarshal(content, &t); err != nil {
		return zero, err
	}
	return t, nil
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
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got HTTP status %s", resp.Status)
	}
	// might want this to be a LimitedReader
	return io.ReadAll(resp.Body)
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
	for _, source := range sources {
		source = strings.TrimRight(source, "/") // TODO: why?
		uri, err := url.Parse(source)
		if err != nil {
			return nil, err
		}
		switch uri.Scheme {
		case "http", "https":
			hs := &httpSource{url: uri.String()}
			hs.dbName = uri.Hostname()
			if opts.HTTPCache != nil {
				hs.cache = opts.HTTPCache
			}
			if opts.HTTPClient != nil {
				hs.c = opts.HTTPClient
			} else {
				hs.c = new(http.Client)
			}
			c.sources = append(c.sources, hs)
		case "file":
			dir, err := web.URLToFilePath(uri)
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
	return c.unionEntries(ctx, func(c Client) ([]*osv.Entry, error) {
		return c.GetByModule(ctx, module)
	})
}

func (c *client) GetByAlias(ctx context.Context, alias string) (entries []*osv.Entry, err error) {
	defer derrors.Wrap(&err, "GetByAlias(%q)", alias)
	return c.unionEntries(ctx, func(c Client) ([]*osv.Entry, error) {
		return c.GetByAlias(ctx, alias)
	})
}

// unionEntries returns the union of all entries obtained by calling get on the client's sources.
func (c *client) unionEntries(ctx context.Context, get func(Client) ([]*osv.Entry, error)) ([]*osv.Entry, error) {
	var entries []*osv.Entry
	// probably should be parallelized
	seen := map[string]bool{}
	for _, s := range c.sources {
		es, err := get(s)
		if err != nil {
			return nil, err // be failure tolerant?
		}
		for _, e := range es {
			if !seen[e.ID] {
				entries = append(entries, e)
				seen[e.ID] = true
			}
		}
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
