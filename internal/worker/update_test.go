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
	h, err := headHash(repo)
	if err != nil {
		t.Fatal(err)
	}
	needsIssue := func(cve *cveschema.CVE) (bool, error) {
		return strings.HasSuffix(cve.ID, "0001"), nil
	}

	ref, err := repo.Reference(plumbing.HEAD, true)
	if err != nil {
		t.Fatal(err)
	}
	commitHash := ref.Hash().String()
	const (
		path1 = "2021/0xxx/CVE-2021-0001.json"
		path2 = "2021/0xxx/CVE-2021-0010.json"
		path3 = "2021/1xxx/CVE-2021-1384.json"
	)
	cve1, bh1 := readCVE(t, repo, path1)
	cve2, bh2 := readCVE(t, repo, path2)
	cve3, bh3 := readCVE(t, repo, path3)

	// CVERecords after the above CVEs are added to an empty DB.
	rs := []*store.CVERecord{
		{
			ID:          cve1.ID,
			CVEState:    cve1.State,
			Path:        path1,
			BlobHash:    bh1,
			CommitHash:  commitHash,
			TriageState: store.TriageStateNeedsIssue, // a public CVE, needsIssue returns true
		},
		{
			ID:          cve2.ID,
			CVEState:    cve2.State,
			Path:        path2,
			BlobHash:    bh2,
			CommitHash:  commitHash,
			TriageState: store.TriageStateNoActionNeeded, // state is reserved
		},
		{
			ID:          cve3.ID,
			CVEState:    cve3.State,
			Path:        path3,
			BlobHash:    bh3,
			CommitHash:  commitHash,
			TriageState: store.TriageStateNoActionNeeded, // state is rejected
		},
	}

	// withTriageState returns a copy of r with the TriageState field changed to ts.
	withTriageState := func(r *store.CVERecord, ts store.TriageState) *store.CVERecord {
		c := *r
		c.BlobHash += "x" // if we don't use a different blob hash, no update will happen
		c.CommitHash = "?"
		c.TriageState = ts
		return &c
	}

	for _, test := range []struct {
		name string
		cur  []*store.CVERecord // current state of DB
		want []*store.CVERecord // expected state after update
	}{
		{
			name: "empty",
			cur:  nil,
			want: rs,
		},
		{
			name: "no change",
			cur:  rs,
			want: rs,
		},
		{
			name: "pre-issue changes",
			cur: []*store.CVERecord{
				// NoActionNeeded -> NeedsIssue
				withTriageState(rs[0], store.TriageStateNoActionNeeded),
				// NeedsIssue -> NoActionNeeded
				withTriageState(rs[1], store.TriageStateNeedsIssue),
				// NoActionNeeded, triage state stays the same but other fields change.
				withTriageState(rs[2], store.TriageStateNoActionNeeded),
			},
			want: rs,
		},
		{
			name: "post-issue changes",
			cur: []*store.CVERecord{
				// IssueCreated -> Updated
				withTriageState(rs[0], store.TriageStateIssueCreated),
				withTriageState(rs[1], store.TriageStateUpdatedSinceIssueCreation),
			},
			want: []*store.CVERecord{
				func() *store.CVERecord {
					c := *rs[0]
					c.TriageState = store.TriageStateUpdatedSinceIssueCreation
					c.TriageStateReason = "CVE changed; needs issue = true"
					return &c
				}(),
				func() *store.CVERecord {
					c := *rs[1]
					c.TriageState = store.TriageStateUpdatedSinceIssueCreation
					c.TriageStateReason = "CVE changed; needs issue = false"
					return &c
				}(),
				rs[2],
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mstore := store.NewMemStore()
			createCVERecords(t, mstore, test.cur)
			if err := doUpdate(ctx, repo, h, mstore, needsIssue); err != nil {
				t.Fatal(err)
			}
			got := mstore.CVERecords()
			want := map[string]*store.CVERecord{}
			for _, cr := range test.want {
				want[cr.ID] = cr
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}

func readCVE(t *testing.T, repo *git.Repository, path string) (*cveschema.CVE, string) {
	blob := findBlob(t, repo, path)
	var cve cveschema.CVE
	if err := json.Unmarshal(readBlob(t, blob), &cve); err != nil {
		t.Fatal(err)
	}
	return &cve, blob.Hash.String()
}

func newTestCVERecord(cve *cveschema.CVE, path, blobHash string, ref *plumbing.Reference, ts store.TriageState) *store.CVERecord {
	r := store.NewCVERecord(cve, path, blobHash)
	r.CommitHash = ref.Hash().String()
	r.TriageState = ts
	return r
}

func createCVERecords(t *testing.T, s store.Store, crs []*store.CVERecord) {
	err := s.RunTransaction(context.Background(), func(_ context.Context, tx store.Transaction) error {
		for _, cr := range crs {
			if err := tx.CreateCVERecord(cr); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
