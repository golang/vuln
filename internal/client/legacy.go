// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/osv"
	"golang.org/x/vuln/internal/web"
)

func NewLegacyClient(source string, opts *Options) (_ Client, err error) {
	source = strings.TrimRight(source, "/")
	uri, err := url.Parse(source)
	if err != nil {
		return nil, err
	}
	switch uri.Scheme {
	case "http", "https":
		return newLegacyHTTPClient(uri, opts), nil
	case "file":
		return newLegacyLocalClient(uri)
	default:
		return nil, fmt.Errorf("source %q has unsupported scheme", uri)
	}
}

// Pseudo-module paths used for parts of the Go system.
// These are technically not valid module paths, so we
// mustn't pass them to module.EscapePath.
// Keep in sync with vulndb/internal/database/generate.go.
var specialCaseModulePaths = map[string]bool{
	internal.GoStdModulePath: true,
	internal.GoCmdModulePath: true,
}

// dbIndex contains a mapping of vulnerable packages to the last time a new
// vulnerability was added to the database.
type dbIndex map[string]time.Time

type httpClient struct {
	c   *http.Client
	url string // the base URI of the source (without trailing "/"). e.g. https://vuln.golang.org

	// indexCalls counts the number of times index() has been called.
	// httpCalls counts the number of times ByModule makes an http request
	// to  vulndb for a module path. Used for testing privacy properties of
	// httpSource.
	indexCalls int
	httpCalls  int
}

func newLegacyHTTPClient(uri *url.URL, opts *Options) (_ *httpClient) {
	hs := &httpClient{url: uri.String()}
	if opts != nil && opts.HTTPClient != nil {
		hs.c = opts.HTTPClient
	} else {
		hs.c = new(http.Client)
	}
	return hs
}

func (hs *httpClient) index(ctx context.Context) (_ dbIndex, err error) {
	hs.indexCalls++ // for testing privacy properties
	defer derrors.Wrap(&err, "Index()")
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/index.json", hs.url), nil)
	if err != nil {
		return nil, err
	}
	resp, err := hs.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var index dbIndex
	if err = json.Unmarshal(b, &index); err != nil {
		return nil, err
	}
	return index, nil
}

func (hs *httpClient) ByModule(ctx context.Context, modulePath string) (_ []*osv.Entry, err error) {
	defer derrors.Wrap(&err, "httpSource.ByModule(%q)", modulePath)
	index, err := hs.index(ctx)
	if err != nil {
		return nil, err
	}
	_, present := index[modulePath]
	if !present {
		return nil, nil
	}
	epath, err := escapeModulePath(modulePath)
	if err != nil {
		return nil, err
	}
	hs.httpCalls++ // for testing privacy properties
	entries, err := httpReadJSON[[]*osv.Entry](ctx, hs, epath+".json")
	if err != nil || entries == nil {
		return nil, err
	}
	return entries, nil
}

// escapeModulePath should be called by cache implementations or other users of
// this package that want to use module paths as filesystem paths. It is like
// golang.org/x/mod/module, but accounts for special paths used by the
// vulnerability database.
func escapeModulePath(path string) (string, error) {
	if specialCaseModulePaths[path] {
		return path, nil
	}
	return module.EscapePath(path)
}

func httpReadJSON[T any](ctx context.Context, hs *httpClient, relativePath string) (T, error) {
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

func (hs *httpClient) LastModifiedTime(ctx context.Context) (_ time.Time, err error) {
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

func (hs *httpClient) readBody(ctx context.Context, url string) ([]byte, error) {
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

type Options struct {
	HTTPClient *http.Client
}

type localClient struct {
	fs fs.FS
}

func newFSClient(fs fs.FS) (*localClient, error) {
	return &localClient{fs: fs}, nil
}

func newLegacyLocalClient(uri *url.URL) (_ *localClient, err error) {
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
	return newFSClient(os.DirFS(dir))
}

func (ls *localClient) ByModule(ctx context.Context, modulePath string) (_ []*osv.Entry, err error) {
	defer derrors.Wrap(&err, "localSource.ByModule(%q)", modulePath)

	index, err := localReadJSON[dbIndex](ls, "index.json")
	if err != nil {
		return nil, err
	}
	// Query index first to be consistent with the way httpSource.ByModule works.
	// Prevents opening and stating files on disk that don't need to be touched. Also
	// solves #56179.
	if _, present := index[modulePath]; !present {
		return nil, nil
	}

	epath, err := escapeModulePath(modulePath)
	if err != nil {
		return nil, err
	}
	e, err := localReadJSON[[]*osv.Entry](ls, epath+".json")
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return e, nil
}

func (ls *localClient) LastModifiedTime(context.Context) (_ time.Time, err error) {
	defer derrors.Wrap(&err, "LastModifiedTime()")

	// Assume that if anything changes, the index does.
	info, err := fs.Stat(ls.fs, "index.json")
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

func localReadJSON[T any](ls *localClient, relativePath string) (T, error) {
	var zero T
	content, err := fs.ReadFile(ls.fs, relativePath)
	if err != nil {
		return zero, err
	}
	var t T
	if err := json.Unmarshal(content, &t); err != nil {
		return zero, err
	}
	return t, nil
}
