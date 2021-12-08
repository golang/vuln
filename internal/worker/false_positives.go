// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"

	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/worker/store"
)

// FalsePositiveCommitHash is the commit used to generate false positive records.
// It is last commit to github.com/CVEProject/cvelist on April 12, 2021.
// The triaged-cve-list file was last edited the next day.
const FalsePositiveCommitHash = "17294f1a2af61a2a2df52ac89cbd7c516f0c4e6a"

func InsertFalsePositives(ctx context.Context, st store.Store) (err error) {
	defer derrors.Wrap(&err, "InsertFalsePositives")

	for i := 0; i < len(falsePositives); i += maxTransactionWrites {
		j := i + maxTransactionWrites
		if j >= len(falsePositives) {
			j = len(falsePositives)
		}
		err := st.RunTransaction(ctx, func(ctx context.Context, tx store.Transaction) error {
			for _, cr := range falsePositives[i:j] {
				if err := tx.CreateCVERecord(cr); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// falsePositivesInserted reports whether the list of false positives has been
// added to the store.
func falsePositivesInserted(ctx context.Context, st store.Store) (bool, error) {
	// Check the first and last IDs. See gen_false_positives.go for the list.
	ids := []string{"CVE-2013-2124", "CVE-2021-3391"}
	for _, id := range ids {
		cr, err := st.GetCVERecord(ctx, id)
		if err != nil {
			return false, err
		}
		if cr == nil {
			return false, nil
		}
	}
	return true, nil
}
