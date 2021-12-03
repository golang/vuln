// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"flag"
	"io/ioutil"
	"strings"
	"testing"

	"golang.org/x/vuln/internal"
)

var (
	githubRepo            = flag.String("repo", "", "GitHub repo (in form owner/repo) to test issues")
	githubAccessTokenFile = flag.String("ghtokenfile", "", "path to file containing GitHub access token")
)

func TestIssueClient(t *testing.T) {
	t.Run("fake", func(t *testing.T) {
		testIssueClient(t, newFakeIssueClient("owner", "repo"))
	})
	t.Run("github", func(t *testing.T) {
		if *githubRepo == "" {
			t.Skip("skipping: no -repo flag")
		}
		owner, repo, found := internal.Cut(*githubRepo, "/")
		if !found {
			t.Fatal("-repo needs to be in the form owner/repo")
		}
		if *githubAccessTokenFile == "" {
			t.Fatal("need -ghtokenfile")
		}
		data, err := ioutil.ReadFile(*githubAccessTokenFile)
		if err != nil {
			t.Fatal(err)
		}
		token := strings.TrimSpace(string(data))
		testIssueClient(t, NewGithubIssueClient(owner, repo, token))
	})
}

func testIssueClient(t *testing.T, c IssueClient) {
	ctx := context.Background()
	iss := &Issue{
		Title:  "vuln worker test",
		Body:   "test of go.googlesource.com/vuln/internal/worker",
		Labels: []string{"testing"},
	}
	num, err := c.CreateIssue(ctx, iss)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("created issue #%d", num)
	gotExists, err := c.IssueExists(ctx, num)
	if err != nil {
		t.Fatal(err)
	}
	if !gotExists {
		t.Error("created issue doesn't exist")
	}
}

type fakeIssueClient struct {
	owner, repo string
	nextID      int
	issues      map[int]*Issue
}

func newFakeIssueClient(owner, repo string) *fakeIssueClient {
	return &fakeIssueClient{
		owner:  owner,
		repo:   repo,
		nextID: 1,
		issues: map[int]*Issue{},
	}
}

func (c *fakeIssueClient) Destination() string {
	return "in memory"
}

func (c *fakeIssueClient) IssueExists(_ context.Context, number int) (bool, error) {
	_, ok := c.issues[number]
	return ok, nil
}

func (c *fakeIssueClient) CreateIssue(_ context.Context, iss *Issue) (number int, err error) {
	number = c.nextID
	c.nextID++
	copy := *iss
	c.issues[number] = &copy
	return number, nil
}
