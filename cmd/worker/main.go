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
	"net/http"
	"os"
	"text/tabwriter"

	"cloud.google.com/go/errorreporting"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/worker"
	"golang.org/x/vuln/internal/worker/log"
	"golang.org/x/vuln/internal/worker/store"
)

var (
	project        = flag.String("project", os.Getenv("GOOGLE_CLOUD_PROJECT"), "project ID")
	namespace      = flag.String("namespace", os.Getenv("VULN_WORKER_NAMESPACE"), "Firestore namespace")
	errorReporting = flag.Bool("reporterrors", os.Getenv("VULN_WORKER_REPORT_ERRORS") == "true", "use the error reporting API")
)

const serviceID = "vuln-worker"

func main() {
	flag.Parse()
	if *project == "" {
		die("need -project or GOOGLE_CLOUD_PROJECT")
	}
	if *namespace == "" {
		die("need -namespace or VULN_WORKER_NAMESPACE")
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
		die("%v", err)
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
	default:
		return fmt.Errorf("unknown command: %q", flag.Arg(1))
	}
}

func listUpdatesCommand(ctx context.Context, st store.Store) error {
	recs, err := st.ListCommitUpdateRecords(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 1, 8, 2, ' ', 0)
	fmt.Fprintf(tw, "Start\tEnd\tCommit\tCVEs Processed\n")
	for _, r := range recs {
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

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
	os.Exit(1)
}
