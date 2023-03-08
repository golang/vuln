// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"time"

	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/web"
	"golang.org/x/vuln/osv"
)

type localSource struct {
	fs fs.FS
}

func newFSClient(fs fs.FS) (*localSource, error) {
	return &localSource{fs: fs}, nil
}

func newFileClient(uri *url.URL) (_ *localSource, err error) {
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
	content, err := fs.ReadFile(ls.fs, epath+".json")
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
	content, err := fs.ReadFile(ls.fs, path.Join(internal.IDDirectory, id+".json"))
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

func (ls *localSource) ListIDs(ctx context.Context) (_ []string, err error) {
	defer derrors.Wrap(&err, "ListIDs()")

	return localReadJSON[[]string](ctx, ls, path.Join(internal.IDDirectory, "index.json"))
}

func (ls *localSource) LastModifiedTime(context.Context) (_ time.Time, err error) {
	defer derrors.Wrap(&err, "LastModifiedTime()")

	// Assume that if anything changes, the index does.
	info, err := fs.Stat(ls.fs, "index.json")
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
