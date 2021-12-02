// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"strings"
	"testing"
	"time"

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
