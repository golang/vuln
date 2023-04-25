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
