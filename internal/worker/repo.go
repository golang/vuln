// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"log"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"golang.org/x/vuln/internal/derrors"
)

const cvelistRepoURL = "https://github.com/CVEProject/cvelist"

// cloneRepo returns a repo by cloning the repo at repoURL.
func cloneRepo(repoURL string) (repo *git.Repository, err error) {
	defer derrors.Wrap(&err, "cloneRepo(%q)", repoURL)
	log.Printf("Cloning %q...", repoURL)
	return git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
		URL:           repoURL,
		ReferenceName: plumbing.HEAD,
		SingleBranch:  true,
		Depth:         1,
		Tags:          git.NoTags,
	})
}

// openRepo returns a repo by opening the repo at the local path dirpath.
func openRepo(dirpath string) (repo *git.Repository, err error) {
	defer derrors.Wrap(&err, "openRepo(%q)", dirpath)
	log.Printf("Opening %q...", dirpath)
	repo, err = git.PlainOpen(dirpath)
	if err != nil {
		return nil, err
	}
	return repo, nil
}

// repoRoot returns the root tree of the repo at HEAD.
func repoRoot(repo *git.Repository) (root *object.Tree, err error) {
	refName := plumbing.HEAD
	ref, err := repo.Reference(refName, true)
	if err != nil {
		return nil, err
	}
	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return nil, err
	}
	return repo.TreeObject(commit.TreeHash)
}
