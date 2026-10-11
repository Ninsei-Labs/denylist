package denylist

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// The repository keeps the three lists that open it whole, each as its header counts it, and with them the
// addresses OFAC alone would miss; the lists added after them are read the same way. Expected members were
// worked out from the sources on 2026-10-09 by hand: four that OFAC tags only USDT (a reader keeping the ETH
// tag misses them), and the UK's and the EU's that OFAC lacks.
func TestTheListsCarryWhatEachSourceListsAndOFACAloneMisses(t *testing.T) {
	ss, err := Read(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(ss) < 3 || ss[0].Name != "OFAC" || ss[1].Name != "UK" || ss[2].Name != "EU" {
		t.Fatalf("the lists are %d, and do not open with OFAC, UK and EU", len(ss))
	}
	for _, s := range ss {
		if !strings.HasPrefix(s.URL, "https://") || s.Published == "" || len(s.Addresses) == 0 {
			t.Errorf("%s: url %q, published %q, %d addresses", s.Name, s.URL, s.Published, len(s.Addresses))
		}
	}
	for _, want := range []struct {
		source int
		addr   string
	}{
		{0, "0x175d44451403edf28469df03a9280c1197adb92c"}, // USDT only
		{0, "0x38735f03b30fbc022ddd06abed01f0ca823c6a94"}, // USDT only
		{0, "0xfac583c0cf07ea434052c49115a4682172ab6b4f"}, // USDT only
		{0, "0xfec8a60023265364d066a1212fde3930f6ae8da7"}, // USDT only
		{1, "0xae05eb856cb28c156d9722094f5eefd5693bc181"}, // Byex, not on OFAC
		{1, "0xd599ac04a1c786972b81e0fef6fb0c3e7b52f8a7"}, // Byex, not on OFAC
		{2, "0x002471b8a185f9980708d0eaec5b289714f56f8d"}, // Garantex ETH, not on OFAC
		{2, "0x3051ca7cb7f6c599fa2f27385ad75010cf0f2bbf"}, // Garantex BSC, not on OFAC
	} {
		if !slices.Contains(ss[want.source].Addresses, want.addr) {
			t.Errorf("%s does not carry %s", ss[want.source].Name, want.addr)
		}
	}
}

// A list file is read whole or not at all: every way one can be wrong refuses it, with the line, and
// none yields a part of the list. Made-up addresses.
func TestAListFileIsReadWholeOrRefused(t *testing.T) {
	const (
		a = "0x1111111111111111111111111111111111111111"
		b = "0x2222222222222222222222222222222222222222"
	)
	head := "name: X\nurl: https://example.org/list\npublished: 2026-10-08\n"
	good := head + "addresses: 2\n\n" + a + " # an entry\n" + b + "\n"
	s, err := Parse([]byte("# a comment\n" + good))
	if err != nil || s.Name != "X" || s.URL != "https://example.org/list" || s.Published != "2026-10-08" || !slices.Equal(s.Addresses, []string{a, b}) {
		t.Fatalf("a good file: %+v, %v", s, err)
	}
	for _, c := range []struct{ name, file, says string }{
		{"count above", head + "addresses: 3\n" + a + "\n" + b + "\n", "counts 3"},
		{"count below", head + "addresses: 1\n" + a + "\n" + b + "\n", "counts 1"},
		{"no count", head + a + "\n", "header needs"},
		{"no name", "url: u\npublished: 2026-10-08\naddresses: 1\n" + a + "\n", "header needs"},
		{"no date", "name: X\nurl: u\naddresses: 1\n" + a + "\n", "header needs"},
		{"not a date", "name: X\nurl: u\npublished: 8 Oct\naddresses: 1\n" + a + "\n", "published"},
		{"none", head + "addresses: 0\n", "no addresses"},
		{"mixed case", head + "addresses: 1\n0x11111111111111111111111111111111111111aA\n", "not an address"},
		{"short", head + "addresses: 1\n0x111\n", "not an address"},
		{"long", head + "addresses: 1\n" + a + "1\n", "not an address"},
		{"twice", head + "addresses: 2\n" + a + "\n" + a + "\n", "listed twice"},
		{"out of order", head + "addresses: 2\n" + b + "\n" + a + "\n", "out of order"},
		{"key after the addresses", head + "addresses: 1\n" + a + "\nnote: x\n", "before the addresses"},
		{"key twice", head + "name: Y\naddresses: 1\n" + a + "\n", "twice"},
		{"unknown key", head + "source: x\naddresses: 1\n" + a + "\n", "unknown key"},
		{"neither", head + "addresses: 1\n" + a + "\nhello\n", "neither"},
		{"negative count", head + "addresses: -1\n", "count"},
	} {
		s, err := Parse([]byte(c.file))
		if err == nil || !strings.Contains(err.Error(), c.says) || s.Addresses != nil {
			t.Errorf("%s: %+v, %v; want a refusal saying %q", c.name, s, err, c.says)
		}
	}
}

// What Parse accepts is a list a reader may use: addresses in EVM form, lower-cased, sorted, each once, as
// many as the header counts.
func FuzzParse(f *testing.F) {
	f.Add([]byte("name: X\nurl: u\npublished: 2026-10-08\naddresses: 1\n0x1111111111111111111111111111111111111111 # n\n"))
	f.Add([]byte("name: X\nurl: u\npublished: 2026-10-08\naddresses: 0\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := Parse(b)
		if err != nil {
			return
		}
		if len(s.Addresses) == 0 || s.Name == "" || s.URL == "" || s.Published == "" {
			t.Fatalf("accepted %+v", s)
		}
		for i, a := range s.Addresses {
			if !IsLower(a) || i > 0 && a <= s.Addresses[i-1] {
				t.Fatalf("accepted %q at %d", a, i)
			}
		}
	})
}

// The status branch's file says the day of the last check and the digest of the files it read, and, while
// main's files are not those, the last day they were and their digest; nothing else reads as one. Each reads
// back as it was written.
func TestTheCheckedFileGivesItsDayAndDigest(t *testing.T) {
	d, m := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	day := func(s string) time.Time { v, _ := time.Parse(time.DateOnly, s); return v }
	for _, c := range []struct {
		line string
		want Status
	}{
		{"checked 2026-10-11 " + d + "\n", Status{Day: day("2026-10-11"), Digest: d}},
		{"checked 2026-10-18 " + d + " main 2026-10-11 " + m + "\n", Status{Day: day("2026-10-18"), Digest: d, MainDay: day("2026-10-11"),
			MainDigest: m}},
	} {
		s, err := ParseChecked([]byte(c.line))
		if err != nil || s != c.want || s.String()+"\n" != c.line {
			t.Errorf("%q: %+v, %v; written back %q", c.line, s, err, s.String())
		}
	}
	for _, bad := range []string{"", "checked 2026-10-11", "checked 11 Oct " + d, "checked 2026-10-11 " + d[:63],
		"checked 2026-10-11 " + strings.ToUpper(d), "Checked 2026-10-11 " + d, "checked 2026-10-11 " + d + " more",
		"checked 2026-10-18 " + d + " main 2026-10-11", "checked 2026-10-18 " + d + " since 2026-10-11 " + m,
		"checked 2026-10-18 " + d + " main 11 Oct " + m, "checked 2026-10-18 " + d + " main 2026-10-11 " + m[:63],
		"checked 2026-10-18 " + d + " main 2026-10-11 " + m + " more"} {
		if _, err := ParseChecked([]byte(bad)); err == nil {
			t.Errorf("%q read as a status", bad)
		}
	}
}

// Each week's status vouches for main's files on the newest day they were the sources' own, whatever pull
// request is open. Weeks of made-up digests: a check finds main's A; one finds B (the pull request opens:
// main's A vouched for on the first week); one finds C while it is open (still the first week); main is set
// to B by hand while the pull request proposes C (no status at hand vouches for B: each keeps only the last
// day main's own files were the sources'), then to X, which no check found; the pull request is merged and
// the check finds main's C. A reader holding a set of files takes the day Vouches gives, or none.
func TestEachCheckVouchesForMainsFilesOnTheLastDayTheyWereTheSources(t *testing.T) {
	week := func(n int) time.Time { return time.Date(2026, 10, 5+7*n, 0, 0, 0, 0, time.UTC) }
	A, B, C, X := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)
	var s Status
	for i, c := range []struct {
		sources, main string
		vouched       map[string]int // digest to the week that vouches for it; absent: none
	}{
		{A, A, map[string]int{A: 1}},
		{B, A, map[string]int{B: 2, A: 1}},
		{C, A, map[string]int{C: 3, A: 1}},
		{C, B, map[string]int{C: 4}},
		{C, X, map[string]int{C: 5}},
		{C, C, map[string]int{C: 6}},
	} {
		s = Next(s, week(i+1), c.sources, c.main)
		back, err := ParseChecked([]byte(s.String()))
		if err != nil || back != s {
			t.Fatalf("week %d: %q read back as %+v, %v", i+1, s.String(), back, err)
		}
		for _, d := range []string{A, B, C, X} {
			day, ok := s.Vouches(d)
			want, vouched := c.vouched[d]
			if ok != vouched || ok && !day.Equal(week(want)) {
				t.Errorf("week %d (%q): files %.1s vouched for on %v (%v), want week %d (%v)", i+1, s.String(), d, day, ok, want, vouched)
			}
		}
	}
}

// The digest of the lists is what sha256sum gives the three files one after the other (the weekly workflow
// writes it so): worked here for two made-up files, "a" and "b", whose SHA-256 together is that of "ab".
func TestTheDigestIsTheFilesInOrder(t *testing.T) {
	if got, want := Digest([]byte("a"), []byte("b")), "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603"; got != want {
		t.Fatalf("digest %s, want %s", got, want)
	}
}
