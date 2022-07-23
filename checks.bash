#!/usr/bin/env bash
# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# This file will be run by `go test`.
# See all_test.go in this directory.

# Ensure that installed go binaries are on the path.
# This bash expression follows the algorithm described at the top of
# `go install help`: first try $GOBIN, then $GOPATH/bin, then $HOME/go/bin.
go_install_dir=${GOBIN:-${GOPATH:-$HOME/go}/bin}
PATH=$PATH:$go_install_dir

source devtools/lib.sh

# ensure_go_binary verifies that a binary exists in $PATH corresponding to the
# given go-gettable URI. If no such binary exists, it is fetched via `go get`.
ensure_go_binary() {
  local binary=$(basename $1)
  if ! [ -x "$(command -v $binary)" ]; then
    info "Installing: $1"
    # Install the binary in a way that doesn't affect our go.mod file.
    go install $1
  fi
}

# verify_header checks that all given files contain the standard header for Go
# projects.
verify_header() {
  if [[ "$@" != "" ]]; then
    for FILE in $@
    do
        line="$(head -4 $FILE)"
        if [[ ! $line == *"The Go Authors. All rights reserved."* ]] &&
         [[ ! $line == "// DO NOT EDIT. This file was copied from" ]]; then
              err "missing license header: $FILE"
        fi
    done
  fi
}

# check_headers checks that all source files that have been staged in this
# commit, and all other non-third-party files in the repo, have a license
# header.
check_headers() {
  if [[ $# -gt 0 ]]; then
    info "Checking listed files for license header"
    verify_header $*
  else
    info "Checking go and sh files for license header"
    # Ignore files in testdata directories.
    verify_header $(find . -name testdata -prune \
      -o -name '*.go' -print \
      -o -name '*.sh' -print)
  fi
}


# check_unparam runs unparam on source files.
check_unparam() {
  if [[ $(go version) = *go1.17* ]]; then
    ensure_go_binary mvdan.cc/unparam
    runcmd unparam ./...
  fi
}

# check_vet runs go vet on source files.
check_vet() {
  runcmd go vet -all ./...
}

# check_staticcheck runs staticcheck on source files.
check_staticcheck() {
  if [[ $(go version) = *go1.17* ]]; then
    ensure_go_binary honnef.co/go/tools/cmd/staticcheck
    runcmd staticcheck ./...
  fi
}

# check_misspell runs misspell on source files.
check_misspell() {
  ensure_go_binary github.com/client9/misspell/cmd/misspell
  runcmd misspell -error .
}

clean_workspace() {
  [[ $(git status --porcelain) == '' ]]
}

# If any vulncheck tests have changed, then either the ResultVersion
# should be different, or "Results unchanged." should be its own
# line in the commit message.
check_vulncheck_result_version() {
  if clean_workspace; then
    fs=$(git diff --name-only HEAD^)
  else
    fs=$(git diff --name-only)
  fi
  tests_modified=false
  for f in $fs; do
    if [[ $f = vulncheck/*_test.go ]]; then
      tests_modified=true
      break
    fi
  done
  if $tests_modified; then
    if git show -s --format=%B | grep -q '^Results unchanged\.'; then
      info 'OK: vulncheck test file modified but commit message says "Results unchanged."'
      return
    fi
    if ! git diff | grep -q 'const ResultVersion'; then
      err "vulncheck test file modified but ResultVersion not changed"
    fi
  fi
}

go_linters() {
  check_vet
  check_staticcheck
  check_misspell
  check_unparam
}

go_modtidy() {
  runcmd go mod tidy
}

runchecks() {
  check_headers
  go_linters
  go_modtidy
}

usage() {
  cat <<EOUSAGE
Usage: $0 [subcommand]
Available subcommands:
  help           - display this help message
EOUSAGE
}

main() {
  case "$1" in
    "-h" | "--help" | "help")
      usage
      exit 0
      ;;
    "")
      runchecks
      ;;
    v)
      check_vulncheck_result_version
      ;;
    *)
      usage
      exit 1
  esac
  if [[ $EXIT_CODE != 0 ]]; then
    err "FAILED; see errors above"
  fi
  exit $EXIT_CODE
}

main $@
