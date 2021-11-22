// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vuln/internal/cveschema"
	"golang.org/x/vuln/internal/worker/store"
)

func TestRepoCVEFiles(t *testing.T) {
	repo, err := readTxtarRepo("testdata/basic.txtar")
	if err != nil {
		t.Fatal(err)
	}
	h, err := headHash(repo)
	if err != nil {
		t.Fatal(err)
	}
	got, err := repoCVEFiles(repo, h)
	if err != nil {
		t.Fatal(err)
	}
	want := []repoFile{
		{dirpath: "2021/0xxx", filename: "CVE-2021-0001.json"},
		{dirpath: "2021/0xxx", filename: "CVE-2021-0010.json"},
		{dirpath: "2021/1xxx", filename: "CVE-2021-1384.json"},
	}

	if diff := cmp.Diff(want, got, cmp.AllowUnexported(repoFile{}), cmpopts.IgnoreFields(repoFile{}, "hash")); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}

func TestDoUpdate(t *testing.T) {
	ctx := context.Background()
	repo, err := readTxtarRepo("testdata/basic.txtar")
	if err != nil {
		t.Fatal(err)
	}
	mstore := store.NewMemStore()
	h, err := headHash(repo)
	if err != nil {
		t.Fatal(err)
	}
	needsIssue := func(cve *cveschema.CVE) (bool, error) {
		return strings.HasSuffix(cve.ID, "0001"), nil
	}
	if err := doUpdate(ctx, repo, h, mstore, needsIssue); err != nil {
		t.Fatal(err)
	}
	ref, err := repo.Reference(plumbing.HEAD, true)
	if err != nil {
		t.Fatal(err)
	}
	r1 := newTestCVERecord(t, repo, ref, "2021/0xxx/CVE-2021-0001.json", store.TriageStateNeedsIssue)
	r10 := newTestCVERecord(t, repo, ref, "2021/0xxx/CVE-2021-0010.json", store.TriageStateNoActionNeeded)
	r384 := newTestCVERecord(t, repo, ref, "2021/1xxx/CVE-2021-1384.json", store.TriageStateNoActionNeeded)
	wantRecords := map[string]*store.CVERecord{
		"CVE-2021-0001": r1,
		"CVE-2021-0010": r10,
		"CVE-2021-1384": r384,
	}
	diff := cmp.Diff(wantRecords, mstore.CVERecords())
	if diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}

func newTestCVERecord(t *testing.T, repo *git.Repository, ref *plumbing.Reference, path string, ts store.TriageState) *store.CVERecord {
	blob := findBlob(t, repo, path)
	r := store.NewCVERecord(readCVE(t, blob), path, blob.Hash.String())
	r.CommitHash = ref.Hash().String()
	r.TriageState = ts
	return r
}

func readCVE(t *testing.T, blob *object.Blob) *cveschema.CVE {
	var cve cveschema.CVE
	if err := json.Unmarshal(readBlob(t, blob), &cve); err != nil {
		t.Fatal(err)
	}
	return &cve
}
