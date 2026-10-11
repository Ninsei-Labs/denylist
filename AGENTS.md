# Working on the Ninsei denylist

Rules for every agent and every person who changes this repository.

## House rules

The organisation's rules, in full in
[CONTRIBUTING.md](https://github.com/Ninsei-Labs/.github/blob/main/CONTRIBUTING.md). The `house-rules`
workflow checks the commit form and the attribution lines on every pull request and push to `main`; the rest
is kept by whoever writes and reviews a change.

- Commit subject and pull request title: `type(scope): summary`, at most 72 characters. Type: feat, fix,
  docs, test, refactor, perf, build, ci, style, chore or revert. Scope: the area changed (`fetch`, `format`,
  `lists`, `ci`), or none when the change spans many. The summary says what the change does, starts lowercase
  and has no full stop. The body says why and how it was checked.
- One commit is one logical change; work-in-progress and fixup commits are squashed into it before merging.
- No tool attribution lines (`Co-authored-by:`, "Generated with") in commits or pull requests.
- No secrets, keys or tokens. The addresses in the lists are the sources' public data; tests use made-up
  addresses.
- English only. Code, commits and pull requests describe the change, not the conversation behind it.

## This repository

- The lists change only by a reviewed pull request, the weekly workflow's or one by hand that says which
  source and designation each address comes from. Never shorten a list to make a check pass.
- A list must fail closed: a source that cannot be read, or reads in another form or much shorter, fails the
  run; it is never written as a list of fewer or no addresses.
- The format is the contract with every reader. A change to it is a change to `denylist.go`, the README and
  every reader, together.
- Before committing: `gofmt -l .` prints nothing, `go vet ./...` and `go test -race ./...` pass.
