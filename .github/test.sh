#!/usr/bin/env bash
# The repository's checks: the ci workflow's test job runs them on every pull request and push to main, and the
# weekly update on the lists it proposes, since a pull request a workflow opens starts no other workflow.
set -euo pipefail
unformatted=$(gofmt -l .)
if [[ -n $unformatted ]]; then
  printf 'not formatted with gofmt:\n%s\n' "$unformatted"
  exit 1
fi
go vet -p 1 ./...
go test -p 1 -race -count=1 ./...
