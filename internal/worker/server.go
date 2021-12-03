// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/safehtml/template"
	"golang.org/x/exp/event"
	"golang.org/x/sync/errgroup"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/gitrepo"
	"golang.org/x/vuln/internal/worker/log"
	"golang.org/x/vuln/internal/worker/store"
)

var staticPath = template.TrustedSourceFromConstant("internal/worker/static")

type Server struct {
	namespace string
	st        store.Store

	indexTemplate *template.Template
}

func NewServer(ctx context.Context, namespace string, st store.Store) (_ *Server, err error) {
	defer derrors.Wrap(&err, "NewServer(%q)", namespace)

	s := &Server{namespace: namespace, st: st}
	s.indexTemplate, err = parseTemplate(staticPath, template.TrustedSourceFromConstant("index.tmpl"))
	if err != nil {
		return nil, err
	}
	s.handle(ctx, "/", s.indexPage)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticPath.String()))))
	s.handle(ctx, "/favicon.ico", func(w http.ResponseWriter, r *http.Request) error {
		http.ServeFile(w, r, filepath.Join(staticPath.String(), "favicon.ico"))
		return nil
	})
	return s, nil
}

func (s *Server) handle(ctx context.Context, pattern string, handler func(w http.ResponseWriter, r *http.Request) error) {
	http.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		traceID := r.Header.Get("X-Cloud-Trace-Context")

		log.Info(ctx, "request start",
			event.Value("httpRequest", r),
			event.String("traceID", traceID))

		r = r.WithContext(log.WithLineLogger(r.Context()))
		w2 := &responseWriter{ResponseWriter: w}
		if err := handler(w2, r); err != nil {
			s.serveError(ctx, w2, r, err)
		}

		log.Info(ctx, "request end",
			event.Value("traceID", traceID),
			event.Duration("latency", time.Since(start)),
			event.Int64("status", translateStatus(w2.status)))
	})
}

func (s *Server) serveError(ctx context.Context, w http.ResponseWriter, r *http.Request, err error) {
	errString := err.Error()
	log.Error(ctx, errString)
	http.Error(w, errString, http.StatusInternalServerError)
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func translateStatus(code int) int64 {
	if code == 0 {
		return http.StatusOK
	}
	return int64(code)
}

// Parse a template.
func parseTemplate(staticPath, filename template.TrustedSource) (*template.Template, error) {
	if staticPath.String() == "" {
		return nil, nil
	}
	templatePath := template.TrustedSourceJoin(staticPath, filename)
	return template.New(filename.String()).Funcs(template.FuncMap{
		"timefmt": FormatTime,
	}).ParseFilesFromTrustedSources(templatePath)
}

var locNewYork *time.Location

func init() {
	var err error
	locNewYork, err = time.LoadLocation("America/New_York")
	if err != nil {
		log.Errorf(context.Background(), "time.LoadLocation: %v", err)
		os.Exit(1)
	}
}

func FormatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.In(locNewYork).Format("2006-01-02 15:04:05")
}

func renderPage(ctx context.Context, w http.ResponseWriter, page interface{}, tmpl *template.Template) (err error) {
	defer derrors.Wrap(&err, "renderPage")

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, page); err != nil {
		return err
	}
	if _, err := io.Copy(w, &buf); err != nil {
		log.Error(ctx, "copying buffer to ResponseWriter", event.Value("error", err))
		return err
	}
	return nil
}

type indexPage struct {
	CVEListRepoURL   string
	Namespace        string
	Updates          []*store.CommitUpdateRecord
	CVEsNeedingIssue []*store.CVERecord
	CVEsUpdatedSince []*store.CVERecord
}

func (s *Server) indexPage(w http.ResponseWriter, r *http.Request) error {

	var (
		updates                    []*store.CommitUpdateRecord
		needingIssue, updatedSince []*store.CVERecord
	)

	g, ctx := errgroup.WithContext(r.Context())
	g.Go(func() error {
		var err error
		updates, err = s.st.ListCommitUpdateRecords(ctx, 10)
		return err
	})
	g.Go(func() error {
		var err error
		needingIssue, err = s.st.ListCVERecordsWithTriageState(ctx, store.TriageStateNeedsIssue)
		return err
	})
	g.Go(func() error {
		var err error
		updatedSince, err = s.st.ListCVERecordsWithTriageState(ctx, store.TriageStateUpdatedSinceIssueCreation)
		return err
	})
	if err := g.Wait(); err != nil {
		return err
	}

	page := indexPage{
		CVEListRepoURL:   gitrepo.CVEListRepoURL,
		Namespace:        s.namespace,
		Updates:          updates,
		CVEsNeedingIssue: needingIssue,
		CVEsUpdatedSince: updatedSince,
	}
	return renderPage(r.Context(), w, page, s.indexTemplate)
}
