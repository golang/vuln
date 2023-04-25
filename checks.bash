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
  binary="$(basename "$1")"
  if ! [ -x "$(command -v "$binary")" ]; then
    info "Installing: $1"
    # Install the binary in a way that doesn't affect our go.mod file.
    go install "$1"
  fi
}

# verify_header checks that all given files contain the standard header for Go
# projects.
verify_header() {
  if [[ "$*" != "" ]]; then
    # TODO(https://go.dev/issue/59733): investigate how to fix error
    # shellcheck disable=SC2048
    for FILE in $*
    do
        line=$(head -4 "$FILE")
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
  echo "check_headers"
  if [[ $# -gt 0 ]]; then
    info "Checking listed files for license header"
    verify_header "$*"
  else
    info "Checking go and sh files for license header"
    # Ignore files in testdata directories.
    verify_header "$(find . -name testdata -prune \
      -o -name '*.go' -print \
      -o -name '*.sh' -print)"
  fi
}

# check_shellcheck runs shellcheck on .bash and .sh files.
check_shellcheck() {
  if ! [ -x "$(command -v shellcheck)" ]; then
    echo "Please install shellcheck. See https://github.com/koalaman/shellcheck#installing."
  fi
  runcmd shellcheck -x checks.bash
  runcmd shellcheck ./**/*.sh
}

go_modtidy() {
  runcmd go mod tidy
}

# runchecks runs all checks and is intended to run as a precommit hook.
runchecks() {
  trybots "$@"

  # These checks only run locally due to a limitation with TryBots.
  check_shellcheck
}

# trybots runs checks supported by TryBots.
trybots() {
  check_headers "$@"
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
      runchecks "$@"
      ;;
    trybots)
      trybots
      ;;
    *)
      usage
      exit 1
  esac
  if [[ "$EXIT_CODE" != 0 ]]; then
    err "FAILED; see errors above"
  fi
  exit "$EXIT_CODE"
}

main "$@"
