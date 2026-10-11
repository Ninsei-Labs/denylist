// Package denylist reads the sanctions lists this repository keeps: the addresses in EVM form that OFAC's
// list of Specially Designated Nationals, the UK Sanctions List and the EU's consolidated list give, one file
// each (ofac.txt, uk.txt, eu.txt). They are written from their sources by cmd/fetch, checked every week, and
// changed only by an approved pull request. Readers fetch them from the main branch (Raw) and the date of
// the last check from the status branch (Checked).
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
	Name      string   // OFAC, UK or EU
	URL       string   // the source it is written from
	Published string   // the date of the source's file it was last written from, YYYY-MM-DD
	Addresses []string // in EVM form, lower-cased, sorted, each once
}

// Files are the lists, in the order readers take them.
var Files = []string{"ofac.txt", "uk.txt", "eu.txt"}

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

// Digest names a set of list files by their bytes: the SHA-256 of ofac.txt, uk.txt and eu.txt one after the
// other, in hex (cat ofac.txt uk.txt eu.txt | sha256sum).
func Digest(files ...[]byte) string {
	h := sha256.New()
	for _, b := range files {
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ParseChecked reads the status branch's checked file, "checked YYYY-MM-DD <digest>": the day of the last
// check against the sources, and the digest of the files that check read.
func ParseChecked(b []byte) (time.Time, string, error) {
	f := strings.Fields(string(b))
	if len(f) != 3 || f[0] != "checked" || len(f[2]) != 64 || strings.Trim(f[2], "0123456789abcdef") != "" {
		return time.Time{}, "", fmt.Errorf("%q is not \"checked YYYY-MM-DD <digest>\"", strings.TrimSpace(string(b)))
	}
	day, err := time.Parse(time.DateOnly, f[1])
	if err != nil {
		return time.Time{}, "", fmt.Errorf("the day of the check %q: %w", f[1], err)
	}
	return day, f[2], nil
}
