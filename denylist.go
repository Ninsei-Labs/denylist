// Package denylist reads the sanctions lists this repository keeps: the addresses in EVM form a source
// gives, one file each (ofac.txt, uk.txt and eu.txt, and the lists read through OpenSanctions since). They
// are written from their sources by cmd/fetch, checked every week, and changed only by an approved pull
// request. Readers fetch them from the main branch (Raw) and the date of the last check from the status
// branch (Checked).
package denylist

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Source is one sanctions list as a file of this repository gives it.
type Source struct {
	Name      string   // OFAC, UK, EU or a list read through OpenSanctions
	URL       string   // the source it is written from
	Published string   // the date of the source's file it was last written from, YYYY-MM-DD
	Addresses []string // in EVM form, lower-cased, sorted, each once
}

// Files are the lists, in the order readers take them. A list is added here, its reader in cmd/fetch and
// its row and notice line in the README, together.
var Files = []string{"ofac.txt", "uk.txt", "eu.txt", "il.txt"}

// Core are the files the status digest covers: the three lists. Naming them here, apart from Files, keeps a
// digest meaning the same thing however many lists the repository grows (cat ofac.txt uk.txt eu.txt |
// sha256sum): a reader that hashed these three files still gets the status's digest, and a list added later
// is not silently hashed into it.
var Core = []string{"ofac.txt", "uk.txt", "eu.txt"}

const (
	// Raw is where a reader fetches a list: Raw + one of Files.
	Raw = "https://raw.githubusercontent.com/Ninsei-Labs/denylist/main/"
	// Checked is the file the weekly check writes on the status branch after every run that read all three
	// sources: "checked YYYY-MM-DD <digest>", the digest of the files it read. It shows the check is alive
	// even when no list changed.
	Checked = "https://raw.githubusercontent.com/Ninsei-Labs/denylist/status/checked"
)

// Read reads the lists from dir, each whole or the whole read refused.
func Read(dir string) ([]Source, error) {
	out := make([]Source, 0, len(Files))
	for _, name := range Files {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		s, err := Parse(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out = append(out, s)
	}
	return out, nil
}

// Parse reads a list file: lines starting with # are comments; the header gives name, url, published and
// addresses, their count; then one address per line, which may end in a # note. An address not in EVM form
// lower-cased, out of order or listed twice, an unknown or repeated key, or a count other than the addresses
// listed refuses the whole file: a list that cannot be read whole is not read at all. So is a list of none,
// which would refuse no one.
func Parse(b []byte) (Source, error) {
	var s Source
	count := -1
	seen := map[string]bool{}
	for i, line := range strings.Split(string(b), "\n") {
		n := i + 1
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "0x") {
			a, _, _ := strings.Cut(line, "#")
			a = strings.TrimSpace(a)
			if !IsLower(a) {
				return Source{}, fmt.Errorf("line %d: %q is not an address: 0x and 40 lower-case hex digits", n, a)
			}
			if k := len(s.Addresses); k > 0 && a <= s.Addresses[k-1] {
				return Source{}, fmt.Errorf("line %d: %s is out of order or listed twice", n, a)
			}
			s.Addresses = append(s.Addresses, a)
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch {
		case !ok || val == "":
			return Source{}, fmt.Errorf("line %d: %q is neither an address nor a key: value", n, line)
		case len(s.Addresses) > 0:
			return Source{}, fmt.Errorf("line %d: the header comes before the addresses", n)
		case seen[key]:
			return Source{}, fmt.Errorf("line %d: %s given twice", n, key)
		}
		seen[key] = true
		switch key {
		case "name":
			s.Name = val
		case "url":
			s.URL = val
		case "published":
			if _, err := time.Parse(time.DateOnly, val); err != nil {
				return Source{}, fmt.Errorf("line %d: published must be a date YYYY-MM-DD, got %q", n, val)
			}
			s.Published = val
		case "addresses":
			c, err := strconv.Atoi(val)
			if err != nil || c < 0 {
				return Source{}, fmt.Errorf("line %d: addresses must be a count, got %q", n, val)
			}
			count = c
		default:
			return Source{}, fmt.Errorf("line %d: unknown key %s", n, key)
		}
	}
	switch {
	case s.Name == "" || s.URL == "" || s.Published == "" || count < 0:
		return Source{}, fmt.Errorf("the header needs name, url, published and addresses")
	case count != len(s.Addresses):
		return Source{}, fmt.Errorf("the header counts %d addresses and the file lists %d", count, len(s.Addresses))
	case count == 0:
		return Source{}, fmt.Errorf("no addresses: a list of none refuses no one")
	}
	return s, nil
}

// IsLower says whether a is an EVM address in lower case: 0x and 40 hex digits.
func IsLower(a string) bool {
	h, ok := strings.CutPrefix(a, "0x")
	return ok && len(h) == 40 && strings.Trim(h, "0123456789abcdef") == ""
}

// Digest names a set of list files by their bytes: the SHA-256 of the files given, one after the other, in
// hex. The status gives it the Core lists (cat ofac.txt uk.txt eu.txt | sha256sum), which keeps the same
// meaning as the lists grow.
func Digest(files ...[]byte) string {
	h := sha256.New()
	for _, b := range files {
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Status is what the status branch's checked file says of the last check against the sources:
// "checked YYYY-MM-DD <digest>", the day of the check and the digest of the files the sources gave that day.
// While main's files are not those (the check's pull request is open), the line goes on
// " main YYYY-MM-DD <digest>": the last day main's files were the check's own, and their digest.
type Status struct {
	Day        time.Time
	Digest     string
	MainDay    time.Time // zero while main's files are the check's own
	MainDigest string
}

// ParseChecked reads the checked file; a line in any other form is no status.
func ParseChecked(b []byte) (Status, error) {
	f := strings.Fields(string(b))
	bad := fmt.Errorf("%q is not \"checked YYYY-MM-DD <digest>\", with \" main YYYY-MM-DD <digest>\" or not",
		strings.TrimSpace(string(b)))
	if (len(f) != 3 && len(f) != 6) || f[0] != "checked" || len(f) == 6 && f[3] != "main" {
		return Status{}, bad
	}
	var s Status
	var err error
	if s.Day, s.Digest, err = dayDigest(f[1], f[2]); err != nil {
		return Status{}, err
	}
	if len(f) == 6 {
		if s.MainDay, s.MainDigest, err = dayDigest(f[4], f[5]); err != nil {
			return Status{}, err
		}
	}
	return s, nil
}

func dayDigest(d, digest string) (time.Time, string, error) {
	if len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" {
		return time.Time{}, "", fmt.Errorf("%q is not a digest: 64 lower-case hex digits", digest)
	}
	day, err := time.Parse(time.DateOnly, d)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("the day %q: %w", d, err)
	}
	return day, digest, nil
}

// String is the status as the checked file holds it, without the newline.
func (s Status) String() string {
	line := "checked " + s.Day.Format(time.DateOnly) + " " + s.Digest
	if s.MainDigest != "" {
		line += " main " + s.MainDay.Format(time.DateOnly) + " " + s.MainDigest
	}
	return line
}

// Vouches is the newest day a check vouched for files of digest d: the check's own day when they are the
// files the sources gave it, the last day main's files were the check's own when they are main's, and no day
// (ok false) for any other files.
func (s Status) Vouches(d string) (day time.Time, ok bool) {
	switch {
	case d == "":
	case d == s.Digest:
		return s.Day, true
	case d == s.MainDigest:
		return s.MainDay, true
	}
	return time.Time{}, false
}

// Next is the status a check on day writes, the sources giving files of digest and main holding files of
// mainDigest: while those differ, the last day main's files were vouched for, carried from prev while they
// are the same files.
func Next(prev Status, day time.Time, digest, mainDigest string) Status {
	s := Status{Day: day, Digest: digest}
	if mainDigest != digest {
		if d, ok := prev.Vouches(mainDigest); ok {
			s.MainDay, s.MainDigest = d, mainDigest
		}
	}
	return s
}
