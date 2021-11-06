// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vuln/internal/cveschema"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func testStore(t *testing.T, s Store) {
	t.Run("Updates", func(t *testing.T) {
		testUpdates(t, s)
	})
	t.Run("CVEs", func(t *testing.T) {
		testCVEs(t, s)
	})
}

func testUpdates(t *testing.T, s Store) {
	ctx := context.Background()
	start := time.Date(2021, time.September, 1, 0, 0, 0, 0, time.Local)

	u1 := &UpdateRecord{
		StartedAt:  start,
		CommitHash: "abc",
		NumTotal:   100,
	}
	must(t, s.CreateUpdateRecord(ctx, u1))
	u1.EndedAt = u1.StartedAt.Add(10 * time.Minute)
	u1.NumAdded = 100
	must(t, s.SetUpdateRecord(ctx, u1))
	u2 := &UpdateRecord{
		StartedAt:  start.Add(time.Hour),
		CommitHash: "def",
		NumTotal:   80,
	}
	must(t, s.CreateUpdateRecord(ctx, u2))
	u2.EndedAt = u2.StartedAt.Add(8 * time.Minute)
	u2.NumAdded = 40
	u2.NumModified = 40
	must(t, s.SetUpdateRecord(ctx, u2))
	got, err := s.ListUpdateRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []*UpdateRecord{u2, u1}
	diff(t, want, got, cmpopts.IgnoreFields(UpdateRecord{}, "UpdatedAt"))
	for _, g := range got {
		if g.UpdatedAt.IsZero() {
			t.Error("zero UpdatedAt field")
		}
	}
}

func testCVEs(t *testing.T, s Store) {
	ctx := context.Background()
	const (
		id1 = "CVE-1905-0001"
		id2 = "CVE-1905-0002"
		id3 = "CVE-1905-0003"
	)
	crs := []*CVERecord{
		{
			ID:          id1,
			Path:        "1905/" + id1 + ".json",
			BlobHash:    "123",
			CommitHash:  "456",
			CVEState:    "PUBLIC",
			TriageState: TriageStateNeedsIssue,
		},
		{
			ID:          id2,
			Path:        "1906/" + id2 + ".json",
			BlobHash:    "abc",
			CommitHash:  "def",
			CVEState:    "RESERVED",
			TriageState: TriageStateNoActionNeeded,
		},
		{
			ID:          id3,
			Path:        "1907/" + id3 + ".json",
			BlobHash:    "xyz",
			CommitHash:  "456",
			CVEState:    "REJECT",
			TriageState: TriageStateNoActionNeeded,
		},
	}

	getCVERecords := func(startID, endID string) []*CVERecord {
		var got []*CVERecord
		err := s.RunTransaction(ctx, func(ctx context.Context, tx Transaction) error {
			var err error
			got, err = tx.GetCVERecords(startID, endID)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	getCVERecord := func(id string) *CVERecord {
		return getCVERecords(id, id)[0]
	}

	createCVERecords(t, ctx, s, crs)

	diff(t, crs[:1], getCVERecords(id1, id1))
	diff(t, crs[1:], getCVERecords(id2, id3))

	// Test SetCVERecord.

	set := func(r *CVERecord) *CVERecord {
		err := s.RunTransaction(ctx, func(ctx context.Context, tx Transaction) error {
			return tx.SetCVERecord(r)
		})
		if err != nil {
			t.Fatal(err)
		}
		return getCVERecord(r.ID)
	}

	// Make sure the first record is the same that we created.
	got := getCVERecord(id1)
	diff(t, crs[0], got)

	// Change the state and the commit hash.
	got.CVEState = cveschema.StateRejected
	got.CommitHash = "999"
	set(got)
	want := *crs[0]
	want.CVEState = cveschema.StateRejected
	want.CommitHash = "999"
	diff(t, &want, got)
}

func createCVERecords(t *testing.T, ctx context.Context, s Store, crs []*CVERecord) {
	err := s.RunTransaction(ctx, func(ctx context.Context, tx Transaction) error {
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

func diff(t *testing.T, want, got interface{}, opts ...cmp.Option) {
	t.Helper()
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}
