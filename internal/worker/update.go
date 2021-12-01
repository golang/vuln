// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/exp/event"
	"golang.org/x/vuln/internal/cveschema"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/worker/log"
	"golang.org/x/vuln/internal/worker/store"
)

// A triageFunc triages a CVE: it decides whether an issue needs to be filed.
type triageFunc func(*cveschema.CVE) (bool, error)

// doUpdate compares the repo at the given commit with the state
// of the DB and updates the DB to match.
//
// needsIssue determines whether a CVE needs an issue to be filed for it.
func doUpdate(ctx context.Context, repo *git.Repository, commitHash plumbing.Hash, st store.Store, needsIssue triageFunc) (err error) {
	// We want the action of reading the old DB record, updating it and
	// writing it back to be atomic. It would be too expensive to do that one
	// record at a time. Ideally we'd process the whole repo commit in one
	// transaction, but Firestore has a limit on how many writes one
	// transaction can do, so the CVE files in the repo are processed in
	// batches, one transaction per batch.
	defer derrors.Wrap(&err, "doUpdate(%s)", commitHash)

	defer func() {
		if err != nil {
			log.Error(ctx, "update failed", event.Value("error", err))
		} else {
			log.Info(ctx, "update succeeded")
		}
	}()

	log.Info(ctx, "update starting", event.String("commit", commitHash.String()))

	// Get all the CVE files.
	// It is cheaper to read all the files from the repo and compare
	// them to the DB in bulk, than to walk the repo and process
	// each file individually.
	files, err := repoCVEFiles(repo, commitHash)
	if err != nil {
		return err
	}
	// Create a new CommitUpdateRecord to describe this run of doUpdate.
	ur := &store.CommitUpdateRecord{
		StartedAt:  time.Now(),
		CommitHash: commitHash.String(),
		NumTotal:   len(files),
	}
	if err := st.CreateCommitUpdateRecord(ctx, ur); err != nil {
		return err
	}

	// Update files in batches.

	// Max Firestore writes per transaction.
	// See https://cloud.google.com/firestore/quotas.
	const batchSize = 500

	for i := 0; i < len(files); i += batchSize {
		j := i + batchSize
		if j > len(files) {
			j = len(files)
		}
		numAdds, numMods, err := updateBatch(ctx, files[i:j], st, repo, commitHash, needsIssue)

		// Change the CommitUpdateRecord in the Store to reflect the results of the transaction.
		if err != nil {
			ur.Error = err.Error()
			if err2 := st.SetCommitUpdateRecord(ctx, ur); err2 != nil {
				return fmt.Errorf("update failed with %w, could not set update record: %v", err, err2)
			}
			return err
		}
		ur.NumProcessed += j - i
		// Add in these two numbers here, instead of in the function passed to
		// RunTransaction, because that function may be executed multiple times.
		ur.NumAdded += numAdds
		ur.NumModified += numMods
		if err := st.SetCommitUpdateRecord(ctx, ur); err != nil {
			return err
		}
	} // end loop

	ur.EndedAt = time.Now()
	return st.SetCommitUpdateRecord(ctx, ur)
}

func updateBatch(ctx context.Context, batch []repoFile, st store.Store, repo *git.Repository, commitHash plumbing.Hash, needsIssue triageFunc) (numAdds, numMods int, err error) {
	startID := idFromFilename(batch[0].filename)
	endID := idFromFilename(batch[len(batch)-1].filename)
	defer derrors.Wrap(&err, "updateBatch(%s-%s)", startID, endID)

	err = st.RunTransaction(ctx, func(ctx context.Context, tx store.Transaction) error {
		numAdds = 0
		numMods = 0
		// Read information about the existing state in the store that's
		// relevant to this batch. Since the entries are sorted, we can read
		// a range of IDS.
		crs, err := tx.GetCVERecords(startID, endID)
		if err != nil {
			return err
		}
		idToRecord := map[string]*store.CVERecord{}
		for _, cr := range crs {
			idToRecord[cr.ID] = cr
		}
		// Determine what needs to be added and modified.
		for _, f := range batch {
			id := idFromFilename(f.filename)
			old := idToRecord[id]
			if old != nil && old.BlobHash == f.hash.String() {
				// No change; do nothing.
				continue
			}
			added, err := handleCVE(repo, f, old, commitHash, needsIssue, tx)
			if err != nil {
				return err
			}
			if added {
				numAdds++
			} else {
				numMods++
			}
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	log.Info(ctx, "update transaction",
		event.String("startID", startID),
		event.String("endID", endID),
		event.Int64("adds", int64(numAdds)),
		event.Int64("mods", int64(numMods)))
	return numAdds, numMods, nil
}

// handleCVE determines how to change the store for a single CVE.
// The CVE will definitely be either added, if it's new, or modified, if it's
// already in the DB.
func handleCVE(repo *git.Repository, f repoFile, old *store.CVERecord, commitHash plumbing.Hash, needsIssue triageFunc, tx store.Transaction) (added bool, err error) {
	defer derrors.Wrap(&err, "handleCVE(%s)", f.filename)

	// Read CVE from repo.
	r, err := blobReader(repo, f.hash)
	if err != nil {
		return false, err
	}
	pathname := path.Join(f.dirpath, f.filename)
	cve := &cveschema.CVE{}
	if err := json.NewDecoder(r).Decode(cve); err != nil {
		return false, err
	}
	needs := false
	if cve.State == cveschema.StatePublic {
		needs, err = needsIssue(cve)
		if err != nil {
			return false, err
		}
	}

	// If the CVE is not in the database, add it.
	if old == nil {
		cr := store.NewCVERecord(cve, path.Join(f.dirpath, f.filename), f.hash.String())
		cr.CommitHash = commitHash.String()
		if needs {
			cr.TriageState = store.TriageStateNeedsIssue
		} else {
			cr.TriageState = store.TriageStateNoActionNeeded
		}
		if err := tx.CreateCVERecord(cr); err != nil {
			return false, err
		}
		return true, nil
	}
	// Change to an existing record.
	mod := *old // copy the old one
	mod.Path = pathname
	mod.BlobHash = f.hash.String()
	mod.CVEState = cve.State
	mod.CommitHash = commitHash.String()
	switch old.TriageState {
	case store.TriageStateNoActionNeeded:
		if needs {
			// Didn't need an issue before, does now.
			mod.TriageState = store.TriageStateNeedsIssue
		}
		// Else don't change the triage state, but we still want
		// to update the other changed fields.
	case store.TriageStateNeedsIssue:
		if !needs {
			// Needed an issue, no longer does.
			mod.TriageState = store.TriageStateNoActionNeeded
		}
		// Else don't change the triage state, but we still want
		// to update the other changed fields.
	case store.TriageStateIssueCreated, store.TriageStateUpdatedSinceIssueCreation:
		// An issue was filed, so a person should revisit this CVE.
		mod.TriageState = store.TriageStateUpdatedSinceIssueCreation
		mod.TriageStateReason = fmt.Sprintf("CVE changed; needs issue = %t", needs)
		// TODO(golang/go#49733): keep a history of the previous states and their commits.
	default:
		return false, fmt.Errorf("unknown TriageState: %q", old.TriageState)
	}
	// If we're here, then mod is a modification to the DB.
	if err := tx.SetCVERecord(&mod); err != nil {
		return false, err
	}
	return false, nil
}

type repoFile struct {
	dirpath  string
	filename string
	hash     plumbing.Hash
}

// repoCVEFiles returns all the CVE files in the given repo commit, sorted by
// name.
func repoCVEFiles(repo *git.Repository, commitHash plumbing.Hash) (_ []repoFile, err error) {
	defer derrors.Wrap(&err, "repoCVEFiles(%s)", commitHash)

	commit, err := repo.CommitObject(commitHash)
	if err != nil {
		return nil, fmt.Errorf("CommitObject: %w", err)
	}
	root, err := repo.TreeObject(commit.TreeHash)
	if err != nil {
		return nil, fmt.Errorf("TreeObject: %v", err)
	}
	files, err := walkFiles(repo, root, "", nil)
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].filename < files[j].filename
	})
	return files, nil
}

// walkFiles collects CVE files from a repo tree.
func walkFiles(repo *git.Repository, tree *object.Tree, dirpath string, files []repoFile) ([]repoFile, error) {
	for _, e := range tree.Entries {
		if e.Mode == filemode.Dir {
			dir, err := repo.TreeObject(e.Hash)
			if err != nil {
				return nil, err
			}
			files, err = walkFiles(repo, dir, path.Join(dirpath, e.Name), files)
			if err != nil {
				return nil, err
			}
		} else if isCVEFilename(e.Name) {
			files = append(files, repoFile{
				dirpath:  dirpath,
				filename: e.Name,
				hash:     e.Hash,
			})
		}
	}
	return files, nil
}

// blobReader returns a reader to the blob with the given hash.
func blobReader(repo *git.Repository, hash plumbing.Hash) (io.Reader, error) {
	blob, err := repo.BlobObject(hash)
	if err != nil {
		return nil, err
	}
	return blob.Reader()
}

// idFromFilename extracts the CVE ID from its filename.
func idFromFilename(name string) string {
	return strings.TrimSuffix(path.Base(name), path.Ext(name))
}

// isCVEFilename reports whether name is the basename of a CVE file.
func isCVEFilename(name string) bool {
	return strings.HasPrefix(name, "CVE-") && path.Ext(name) == ".json"
}
