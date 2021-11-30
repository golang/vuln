// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command worker runs the vuln worker server.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"

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
	if os.Getenv("PORT") == "" && flag.NArg() == 0 {
		die("need PORT or command-line args")
	}

	ctx := log.WithLineLogger(context.Background())

	fstore, err := store.NewFireStore(ctx, *project, *namespace)
	if err != nil {
		die("firestore: %v", err)
	}

	if *errorReporting {
		reportingClient, err := errorreporting.NewClient(ctx, *project, errorreporting.Config{
			ServiceName: serviceID,
			OnError: func(err error) {
				log.Errorf(ctx, "Error reporting failed: %v", err)
			},
		})
		if err != nil {
			die("errorreporting: %v", err)
		}
		derrors.SetReportingClient(reportingClient)
	}

	_, err = worker.NewServer(ctx, *namespace, fstore)
	if err != nil {
		die("NewServer: %v", err)
	}
	addr := ":" + os.Getenv("PORT")
	log.Infof(ctx, "Listening on addr %s", addr)
	die("listening: %v", http.ListenAndServe(addr, nil))
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
	os.Exit(1)
}
