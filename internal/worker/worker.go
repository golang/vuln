// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

// This file has the public API of the worker, used by cmd/worker as well
// as the server in this package.

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"golang.org/x/sync/errgroup"
	vulnc "golang.org/x/vuln/client"
	"golang.org/x/vuln/internal/cveschema"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/gitrepo"
	"golang.org/x/vuln/internal/worker/store"
)

// UpdateCommit performs an update on the store using the given commit.
// Unless force is true, it checks that the update makes sense before doing it.
func UpdateCommit(ctx context.Context, repoPath, commitHash string, st store.Store, pkgsiteURL string, force bool) (err error) {
	defer derrors.Wrap(&err, "RunCommitUpdate(%q, %q, force=%t)", repoPath, commitHash, force)

	repo, err := gitrepo.CloneOrOpen(repoPath)
	if err != nil {
		return err
	}
	ch := plumbing.NewHash(commitHash)
	if !force {
		if err := checkUpdate(ctx, repo, ch, st); err != nil {
			return err
		}
	}
	knownVulnIDs, err := readVulnDB(ctx)
	if err != nil {
		return err
	}
	_, err = doUpdate(ctx, repo, ch, st, knownVulnIDs, func(cve *cveschema.CVE) (bool, error) {
		return TriageCVE(ctx, cve, pkgsiteURL)
	})
	return err
}

// checkUpdate performs sanity checks on a potential update.
// It verifies that there is not an update currently in progress,
// and it makes sure that the update is to a more recent commit.
func checkUpdate(ctx context.Context, repo *git.Repository, commitHash plumbing.Hash, st store.Store) error {
	urs, err := st.ListCommitUpdateRecords(ctx, 1)
	if err != nil {
		return err
	}
	if len(urs) == 0 {
		// No updates, we're good.
		return nil
	}
	lu := urs[0]
	if lu.EndedAt.IsZero() {
		return &CheckUpdateError{
			msg: fmt.Sprintf("latest update started %s ago and has not finished", time.Since(lu.StartedAt)),
		}
	}
	if lu.Error != "" {
		return &CheckUpdateError{
			msg: fmt.Sprintf("latest update finished with error %q", lu.Error),
		}
	}
	commit, err := repo.CommitObject(commitHash)
	if err != nil {
		return err
	}
	if commit.Committer.When.Before(lu.CommitTime) {
		return &CheckUpdateError{
			msg: fmt.Sprintf("commit %s time %s is before latest update commit %s time %s",
				commitHash, commit.Committer.When.Format(time.RFC3339),
				lu.CommitHash, lu.CommitTime.Format(time.RFC3339)),
		}
	}
	return nil
}

// CheckUpdateError is an error returned from UpdateCommit that can be avoided
// calling UpdateCommit with force set to true.
type CheckUpdateError struct {
	msg string
}

func (c *CheckUpdateError) Error() string {
	return c.msg
}

const vulnDBURL = "https://storage.googleapis.com/go-vulndb"

// readVulnDB returns a list of all CVE IDs in the Go vuln DB.
func readVulnDB(ctx context.Context) ([]string, error) {
	const concurrency = 4

	client, err := vulnc.NewClient([]string{vulnDBURL}, vulnc.Options{})
	if err != nil {
		return nil, err
	}

	goIDs, err := client.ListIDs(ctx)
	if err != nil {
		return nil, err
	}
	var (
		mu     sync.Mutex
		cveIDs []string
	)
	sem := make(chan struct{}, concurrency)
	g, ctx := errgroup.WithContext(ctx)
	for _, id := range goIDs {
		id := id
		sem <- struct{}{}
		g.Go(func() error {
			defer func() { <-sem }()
			e, err := client.GetByID(ctx, id)
			if err != nil {
				return err
			}
			// Assume all the aliases are CVE IDs.
			mu.Lock()
			cveIDs = append(cveIDs, e.Aliases...)
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return cveIDs, nil
}
