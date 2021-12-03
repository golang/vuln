// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command worker runs the vuln worker server.
// It can also be used to perform actions from the command line
// by providing a sub-command.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

	"cloud.google.com/go/errorreporting"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/gitrepo"
	"golang.org/x/vuln/internal/worker"
	"golang.org/x/vuln/internal/worker/log"
	"golang.org/x/vuln/internal/worker/store"
)

var (
	project         = flag.String("project", os.Getenv("GOOGLE_CLOUD_PROJECT"), "project ID (required)")
	namespace       = flag.String("namespace", os.Getenv("VULN_WORKER_NAMESPACE"), "Firestore namespace (required)")
	errorReporting  = flag.Bool("report-errors", os.Getenv("VULN_WORKER_REPORT_ERRORS") == "true", "use the error reporting API")
	localRepoPath   = flag.String("local-cve-repo", "", "path to local repo, instead of cloning remote")
	force           = flag.Bool("force", false, "force an update to happen")
	limit           = flag.Int("limit", 0, "limit on number of things to list or issues to create (0 means unlimited)")
	issueRepo       = flag.String("issue-repo", "", "repo to create issues in")
	githubTokenFile = flag.String("ghtokenfile", "", "path to file containing GitHub access token (for creating issues)")
)

const (
	pkgsiteURL = "https://pkg.go.dev"
	serviceID  = "vuln-worker"
)

func main() {
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "usage:")
		fmt.Fprintln(out, "worker FLAGS")
		fmt.Fprintln(out, "  run as a server, listening at the PORT env var")
		fmt.Fprintln(out, "worker FLAGS SUBCOMMAND ...")
		fmt.Fprintln(out, "  run as a command-line tool, executing SUBCOMMAND")
		fmt.Fprintln(out, "  subcommands:")
		fmt.Fprintln(out, "    update COMMIT: perform an update operation")
		fmt.Fprintln(out, "    list-updates: display info about update operations")
		fmt.Fprintln(out, "    list-cves TRIAGE_STATE: display info about CVE records")
		fmt.Fprintln(out, "    create-issues: create issues for CVEs that need them")
		fmt.Fprintln(out, "flags:")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *project == "" {
		dieWithUsage("need -project or GOOGLE_CLOUD_PROJECT")
	}
	if *namespace == "" {
		dieWithUsage("need -namespace or VULN_WORKER_NAMESPACE")
	}
	ctx := log.WithLineLogger(context.Background())

	fstore, err := store.NewFireStore(ctx, *project, *namespace)
	if err != nil {
		die("firestore: %v", err)
	}
	if flag.NArg() > 0 {
		err = runCommandLine(ctx, fstore)
	} else {
		err = runServer(ctx, fstore)
	}
	if err != nil {
		dieWithUsage("%v", err)
	}
}

func runServer(ctx context.Context, st store.Store) error {
	if os.Getenv("PORT") == "" {
		return errors.New("need PORT")
	}

	if *errorReporting {
		reportingClient, err := errorreporting.NewClient(ctx, *project, errorreporting.Config{
			ServiceName: serviceID,
			OnError: func(err error) {
				log.Errorf(ctx, "Error reporting failed: %v", err)
			},
		})
		if err != nil {
			return err
		}
		derrors.SetReportingClient(reportingClient)
	}

	_, err := worker.NewServer(ctx, *namespace, st)
	if err != nil {
		return err
	}
	addr := ":" + os.Getenv("PORT")
	log.Infof(ctx, "Listening on addr %s", addr)
	return fmt.Errorf("listening: %v", http.ListenAndServe(addr, nil))
}

const timeFormat = "2006/01/02 15:04:05"

func runCommandLine(ctx context.Context, st store.Store) error {
	switch flag.Arg(0) {
	case "list-updates":
		return listUpdatesCommand(ctx, st)
	case "list-cves":
		return listCVEsCommand(ctx, st, flag.Arg(1))
	case "update":
		if flag.NArg() != 2 {
			return errors.New("usage: update COMMIT")
		}
		return updateCommand(ctx, st, flag.Arg(1))
	case "create-issues":
		return createIssuesCommand(ctx, st)

	default:
		return fmt.Errorf("unknown command: %q", flag.Arg(1))
	}
}

func listUpdatesCommand(ctx context.Context, st store.Store) error {
	recs, err := st.ListCommitUpdateRecords(ctx, 0)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 1, 8, 2, ' ', 0)
	fmt.Fprintf(tw, "Start\tEnd\tCommit\tCVEs Processed\n")
	for i, r := range recs {
		if *limit > 0 && i >= *limit {
			break
		}
		endTime := "unfinished"
		if !r.EndedAt.IsZero() {
			endTime = r.EndedAt.Format(timeFormat)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d/%d (added %d, modified %d)\n",
			r.StartedAt.Format(timeFormat),
			endTime,
			r.CommitHash,
			r.NumProcessed, r.NumTotal, r.NumAdded, r.NumModified)
	}
	return tw.Flush()
}

func listCVEsCommand(ctx context.Context, st store.Store, triageState string) error {
	ts := store.TriageState(triageState)
	if err := ts.Validate(); err != nil {
		return err
	}
	crs, err := st.ListCVERecordsWithTriageState(ctx, ts)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 1, 8, 2, ' ', 0)
	fmt.Fprintf(tw, "ID\tCVEState\tCommit\tReason\tIssue\tIssue Created\n")
	for i, r := range crs {
		if *limit > 0 && i >= *limit {
			break
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.ID, r.CVEState, r.CommitHash, r.TriageStateReason, r.IssueReference, worker.FormatTime(r.IssueCreatedAt))
	}
	return tw.Flush()
}

func updateCommand(ctx context.Context, st store.Store, commitHash string) error {
	repoPath := gitrepo.CVEListRepoURL
	if *localRepoPath != "" {
		repoPath = *localRepoPath
	}
	err := worker.UpdateCommit(ctx, repoPath, commitHash, st, pkgsiteURL, *force)
	if cerr := new(worker.CheckUpdateError); errors.As(err, &cerr) {
		return fmt.Errorf("%w; use -force to override", cerr)
	}
	return err
}

func createIssuesCommand(ctx context.Context, st store.Store) error {
	owner, repoName, err := worker.ParseGithubRepo(*issueRepo)
	if err != nil {
		return err
	}
	if *githubTokenFile == "" {
		return errors.New("need -ghtokenfile")
	}
	data, err := ioutil.ReadFile(*githubTokenFile)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(data))
	return worker.CreateIssues(ctx, st, worker.NewGithubIssueClient(owner, repoName, token), *limit)
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
	os.Exit(1)
}

func dieWithUsage(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
	flag.Usage()
	os.Exit(1)
}
