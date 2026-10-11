# Ninsei denylist

The sanctions lists a Ninsei maker refuses to quote to: the addresses in EVM form that OFAC's list of
Specially Designated Nationals, the UK Sanctions List and the EU's consolidated list give. One file each, the
one source for makers, the site and any interface on the SDK.

| File | Source | How it is written |
|---|---|---|
| `ofac.txt` | OFAC's SDN list (U.S. Department of the Treasury) | every "Digital Currency Address" of any coin whose value is an address in EVM form, with the entries that list it |
| `uk.txt` | The UK Sanctions List (FCDO) | the addresses in EVM form its designations give in free text, each noted with its designation by hand |
| `eu.txt` | The EU's consolidated list of financial sanctions | the addresses in EVM form its entries give in free text, each noted with its entry by hand |

A list of sanctioned addresses is the least a maker screens: a sanctioned party can use a fresh address, and
the money that funds a swap can come from anywhere. It does not certify where funds come from.

## Format

Lines starting with `#` are comments. A header gives `name`, `url` (the source), `published` (the date of
the source's file it was last written from, `YYYY-MM-DD`) and `addresses` (their count). Then one address
per line: `0x` and 40 lower-case hex digits, sorted, each once, which may end in `# note`. A file that breaks
any of this, or lists no address, is no list: a reader takes a file whole or not at all.

The Go package `github.com/Ninsei-Labs/denylist` reads the files (`Parse`, `Read`), names them (`Files`)
and their status (`ParseChecked`, `Digest`).

## Reading the lists

- The files: `https://raw.githubusercontent.com/Ninsei-Labs/denylist/main/ofac.txt`, `uk.txt` and `eu.txt`.
- The status of the weekly check: `https://raw.githubusercontent.com/Ninsei-Labs/denylist/status/checked`,
  one line, `checked YYYY-MM-DD <digest>`: the day of the last check that read all three sources, and the
  SHA-256 of the three files as the sources gave them then (`cat ofac.txt uk.txt eu.txt | sha256sum`). When
  it is not the digest of the files on main, the sources have changed and the change awaits review.

A reader should take the three files whole, refuse a file that does not read, keep the lists it had when a
read fails, and treat lists whose last check is old as stale: the check runs every week.

## How the lists change

Every Monday a workflow (`.github/workflows/update.yml`) reads the three sources with `go run ./cmd/fetch`.
When a list differs from its source it opens one pull request, or updates the open one, listing every
address added and removed with its source; nothing merges by itself, and main takes a change only with a
code owner's review. A new address from the UK or EU list comes with the day it was found as its note: the
reviewer replaces it with the designation it comes from. A source that cannot be read, or lists a fifth
fewer addresses than its file, fails the run and opens an issue: such a drop is checked by hand. Every run
that read all three sources writes the status above, so a reader sees the check is alive even when no list
changed.

To check by hand: `go run ./cmd/fetch -check` writes nothing and fails when a list differs from its source;
`go run ./cmd/fetch` writes the files.

## Licence

The code (the Go package, `cmd/fetch` and the workflows) is under the MIT licence ([LICENSE](LICENSE)). The
lists (`ofac.txt`, `uk.txt`, `eu.txt`), as compiled here, are dedicated to the public domain under CC0 1.0
([LICENSE-DATA](LICENSE-DATA)).

### Notice

CC0 covers this compilation. The UK's and the EU's own terms still ask whoever republishes their data to
attribute it: keep this notice with the lists.

- `ofac.txt`: Source: U.S. Department of the Treasury, Office of Foreign Assets Control, Specially Designated
  Nationals and Blocked Persons List. A work of the US government, in the public domain.
- `uk.txt`: Contains public sector information licensed under the Open Government Licence v3.0
  (<https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/>). Source: UK Sanctions List,
  Foreign, Commonwealth and Development Office.
- `eu.txt`: Source: European Commission, Consolidated list of persons, groups and entities subject to EU
  financial sanctions. Reused under the Commission's reuse policy (Commission Decision 2011/833/EU), with the
  source acknowledged.
