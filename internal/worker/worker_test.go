// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vuln/internal/worker/log"
	"golang.org/x/vuln/internal/worker/store"
)

func TestCheckUpdate(t *testing.T) {
	ctx := context.Background()
	tm := time.Date(2021, 1, 26, 0, 0, 0, 0, time.Local)
	repo, err := readTxtarRepo("testdata/basic.txtar", tm)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		latestUpdate *store.CommitUpdateRecord
		want         string // non-empty => substring of error message
	}{
		// no latest update, no problem
		{nil, ""},
		// latest update finished and commit is earlier; no problem
		{
			&store.CommitUpdateRecord{
				EndedAt:    time.Now(),
				CommitHash: "abc",
				CommitTime: tm.Add(-time.Hour),
			},
			"",
		},
		// latest update didn't finish
		{
			&store.CommitUpdateRecord{
				CommitHash: "abc",
				CommitTime: tm.Add(-time.Hour),
			},
			"not finish",
		},
		// latest update finished with error
		{
			&store.CommitUpdateRecord{
				CommitHash: "abc",
				CommitTime: tm.Add(-time.Hour),
				EndedAt:    time.Now(),
				Error:      "bad",
			},
			"with error",
		},
		// latest update finished on a later commit
		{
			&store.CommitUpdateRecord{
				EndedAt:    time.Now(),
				CommitHash: "abc",
				CommitTime: tm.Add(time.Hour),
			},
			"before",
		},
	} {
		mstore := store.NewMemStore()
		if test.latestUpdate != nil {
			if err := mstore.CreateCommitUpdateRecord(ctx, test.latestUpdate); err != nil {
				t.Fatal(err)
			}
		}
		got := checkUpdate(ctx, repo, headCommit(t, repo).Hash, mstore)
		if got == nil && test.want != "" {
			t.Errorf("%+v:\ngot no error, wanted %q", test.latestUpdate, test.want)
		} else if got != nil && !strings.Contains(got.Error(), test.want) {
			t.Errorf("%+v:\ngot '%s', does not contain %q", test.latestUpdate, got, test.want)
		}
	}
}

func TestCreateIssues(t *testing.T) {
	ctx := log.WithLineLogger(context.Background())
	mstore := store.NewMemStore()
	ic := newFakeIssueClient()

	crs := []*store.CVERecord{
		{
			ID:          "ID1",
			BlobHash:    "bh1",
			CommitHash:  "ch",
			Path:        "path1",
			TriageState: store.TriageStateNeedsIssue,
		},
		{
			ID:          "ID2",
			BlobHash:    "bh2",
			CommitHash:  "ch",
			Path:        "path2",
			TriageState: store.TriageStateNoActionNeeded,
		},
		{
			ID:          "ID3",
			BlobHash:    "bh3",
			CommitHash:  "ch",
			Path:        "path3",
			TriageState: store.TriageStateIssueCreated,
		},
	}
	createCVERecords(t, mstore, crs)

	if err := CreateIssues(ctx, mstore, ic, 0); err != nil {
		t.Fatal(err)
	}

	var wants []*store.CVERecord
	for _, r := range crs {
		copy := *r
		wants = append(wants, &copy)
	}
	wants[0].TriageState = store.TriageStateIssueCreated
	wants[0].IssueReference = "inMemory#1"

	gotRecs := mstore.CVERecords()
	if len(gotRecs) != len(wants) {
		t.Fatalf("wrong number of records: got %d, want %d", len(gotRecs), len(wants))
	}
	for _, want := range wants {
		got := gotRecs[want.ID]
		if !cmp.Equal(got, want, cmpopts.IgnoreFields(store.CVERecord{}, "IssueCreatedAt")) {
			t.Errorf("got  %+v\nwant %+v", got, want)
		}
	}
}
