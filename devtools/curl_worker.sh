#!/bin/bash

# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Visit a URL on the vuln worker.

set -e

source devtools/lib.sh || { echo "Are you at repo root?"; exit 1; }

env=$1
path=$2

case $env in
  dev)
    svc_acct=impersonate-for-iap@go-discovery-exp.iam.gserviceaccount.com
    oauth_client_id=55665122702-tk2rogkaalgru7pqibvbltqs7geev8j5.apps.googleusercontent.com
    url=https://dev-vuln-worker-ku6ias4ydq-uc.a.run.app
    ;;
  prod)
    svc_acct=impersonate-for-iap@go-discovery.iam.gserviceaccount.com
    oauth_client_id=117187402928-nl3u0qo5l2c2hhsuf2qj8irsfb3l6hfc.apps.googleusercontent.com
    url=TDB
    ;;
  *) die "usage: $0 (dev | prod)"
esac

tok=$(gcloud --impersonate-service-account $svc_acct auth print-identity-token --audiences $oauth_client_id  --include-email)

if [[ $path = update* || $path = issue* ]]; then
  args="-X POST"
fi

curl $args -i -H "Authorization: Bearer $tok" $url/$path
