package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Ninsei-Labs/denylist"
)

// sdnDoc is a made-up SDN.XML in the shape of OFAC's file (the 2026-10-08 publication's elements and
// namespace), with the entries given.
func sdnDoc(count string, entries ...string) string {
	return `<?xml version="1.0" standalone="yes"?>
<sdnList xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="` + sdnNamespace + `">
  <publshInformation><Publish_Date>10/08/2026</Publish_Date><Record_Count>` + count + `</Record_Count></publshInformation>
` + strings.Join(entries, "\n") + "\n</sdnList>\n"
}

func entry(last, first string, ids ...[2]string) string {
	var b strings.Builder
	b.WriteString("<sdnEntry><uid>1</uid><lastName>" + last + "</lastName>")
	if first != "" {
		b.WriteString("<firstName>" + first + "</firstName>")
	}
	b.WriteString("<sdnType>Entity</sdnType><idList>")
	for _, id := range ids {
		b.WriteString("<id><uid>2</uid><idType>" + id[0] + "</idType><idNumber>" + id[1] + "</idNumber></id>")
	}
	return b.String() + "</idList></sdnEntry>"
}

// Every address in EVM form under any coin's tag is taken, lower-cased, once, with each entry that lists it;
// other chains' addresses, other ids and near misses are not.
func TestTheSDNListGivesEveryAddressInEVMFormUnderAnyTag(t *testing.T) {
	const (
		eth  = "0xAaAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		usdt = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		bsc  = "0xcccccccccccccccccccccccccccccccccccccccc"
	)
	doc := sdnDoc("4",
		entry("GROUP ONE", "", [2]string{"Digital Currency Address - ETH", eth}, [2]string{"Digital Currency Address - XBT", "bc1qexample"}),
		entry("DOE", "Jane", [2]string{"Digital Currency Address - USDT", " " + usdt + " "}, [2]string{"Digital Currency Address - ETH", strings.ToLower(eth)}),
		entry("GROUP TWO", "", [2]string{"Digital Currency Address - BSC", bsc}, [2]string{"Digital Currency Address - TRX", "TExample"},
			[2]string{"Digital Currency Address - ETH", bsc + "d"}, [2]string{"Digital Currency Address - ETH", "0x123"}),
		entry("COMPANY", "", [2]string{"Passport", "0xdddddddddddddddddddddddddddddddddddddddd"}))
	l, err := readSDN(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		strings.ToLower(eth): {"GROUP ONE", "DOE, Jane"},
		usdt:                 {"DOE, Jane"},
		bsc:                  {"GROUP TWO"},
	}
	if l.published != "2026-10-08" || len(l.names) != len(want) {
		t.Fatalf("published %q, %d addresses %v; want 2026-10-08 and %d", l.published, len(l.names), l.names, len(want))
	}
	for a, names := range want {
		if !slices.Equal(l.names[a], names) {
			t.Errorf("%s: %v, want %v", a, l.names[a], names)
		}
	}
	// Written out, the list reads back as the same addresses with the publication's date.
	read := map[string]string{}
	for a, names := range l.names {
		read[a] = strings.Join(names, "; ")
	}
	s, err := denylist.Parse(file(denylist.Source{Name: "OFAC", URL: "https://example.org/SDN_XML.ZIP"}, l.published, read))
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "OFAC" || s.Published != "2026-10-08" || !slices.Equal(s.Addresses, []string{strings.ToLower(eth), usdt, bsc}) {
		t.Fatalf("ofac.txt reads back as %+v", s)
	}
}

// A file in another form is never read as a list of fewer addresses: each way it can differ fails.
func TestAnSDNFileInAnotherFormIsRefused(t *testing.T) {
	one := entry("GROUP", "", [2]string{"Digital Currency Address - ETH", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	full := sdnDoc("1", one)
	for _, c := range []struct{ name, doc, says string }{
		{"another namespace", strings.Replace(full, sdnNamespace, "http://tempuri.org/sdnList.xsd", 1), "not sdnList"},
		{"cut short", full[:len(full)/2], "EOF"},
		{"entries counted otherwise", sdnDoc("2", one), "counts 2"},
		{"no count", strings.Replace(full, "<Record_Count>1</Record_Count>", "", 1), "count"},
		{"no date", strings.Replace(full, "<Publish_Date>10/08/2026</Publish_Date>", "", 1), "date"},
		{"a date in another form", strings.Replace(full, "10/08/2026", "2026-10-08", 1), "date"},
		{"no digital currency address", sdnDoc("1", entry("GROUP", "", [2]string{"Passport", "X1"})), "no digital currency"},
		{"none in EVM form", sdnDoc("1", entry("GROUP", "", [2]string{"Digital Currency Address - XBT", "bc1q"})), "no address in EVM form"},
		{"not XML", "<html>maintenance</html>", "not sdnList"},
		{"empty", "", "no document"},
	} {
		if l, err := readSDN(strings.NewReader(c.doc)); err == nil || !strings.Contains(err.Error(), c.says) || len(l.names) > 0 {
			t.Errorf("%s: %d addresses, %v; want a refusal saying %q", c.name, len(l.names), err, c.says)
		}
	}
}

func FuzzReadSDN(f *testing.F) {
	f.Add([]byte(sdnDoc("1", entry("G", "", [2]string{"Digital Currency Address - ETH", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}))))
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := readSDN(bytes.NewReader(b))
		if err != nil {
			return
		}
		if l.published == "" || len(l.names) == 0 {
			t.Fatalf("accepted %+v", l)
		}
		for a := range l.names {
			if !evmForm.MatchString(a) {
				t.Fatalf("accepted %q", a)
			}
		}
	})
}

// The UK and EU files write addresses in free text: each in EVM form is found however it is written, and a
// longer run of hex digits is not one.
func TestEveryAddressInFreeTextIsFound(t *testing.T) {
	const a, b = "0x1111111111111111111111111111111111111111", "0x2222222222222222222222222222222222222222"
	upper := "0x" + strings.ToUpper(a[2:])
	for _, c := range []struct {
		text string
		want []string
	}{
		{"ETH: " + a, []string{a}},
		{"Digital Currency Address: ETH " + upper + ".", []string{a}},
		{a + "," + b, []string{a, b}},
		{"<OtherInformation>" + b + "</OtherInformation>" + a, []string{a, b}},
		{"(" + a + ")\n" + a, []string{a}},
		{"tx " + a + "11223344", nil},
		{"x" + a, nil},
		{"0x" + a[3:], nil},
		{"", nil},
	} {
		if got := evmIn([]byte(c.text)); !slices.Equal(got, c.want) {
			t.Errorf("%q: %v, want %v", c.text, got, c.want)
		}
	}
}

func FuzzEvmIn(f *testing.F) {
	f.Add([]byte("ETH: 0x1111111111111111111111111111111111111111 and 0x2"))
	f.Fuzz(func(t *testing.T, b []byte) {
		got := evmIn(b)
		for i, a := range got {
			if !evmForm.MatchString(a) || i > 0 && a <= got[i-1] {
				t.Fatalf("%q from %q", a, b)
			}
			if !bytes.Contains(bytes.ToLower(b), []byte(a)) {
				t.Fatalf("%q is not in the text", a)
			}
		}
	})
}

// zipped is an SDN_XML.ZIP holding doc as SDN.XML.
func zipped(t *testing.T, doc string) []byte {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, err := z.Create("SDN.XML")
	if err == nil {
		_, err = w.Write([]byte(doc))
	}
	if err == nil {
		err = z.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// A run writes each list as its source gives it now: OFAC's addresses with the entries that list them, the
// UK's and the EU's with the notes they had and the day a new one was found; it summarises every address
// added and removed with its source; with -check it writes nothing; and a source that lists a fifth fewer
// addresses than its file fails the whole run, nothing written. Made-up sources and addresses.
func TestARunWritesTheListsAsTheirSourcesGiveThem(t *testing.T) {
	const (
		a = "0x1111111111111111111111111111111111111111"
		b = "0x2222222222222222222222222222222222222222"
		c = "0x3333333333333333333333333333333333333333"
		d = "0x4444444444444444444444444444444444444444"
		e = "0x5555555555555555555555555555555555555555"
	)
	now := time.Date(2026, 10, 12, 6, 17, 0, 0, time.UTC)
	for _, tc := range []struct {
		name               string
		ofac, uk, eu       string // what each source gives
		check              bool
		failed             string
		ofacFile, ukFile   []string // the addresses each file then holds
		summary, unchanged []string // what the summary says, and the lists it leaves out
	}{
		{name: "the same", ofac: sdnDoc("2", entry("GROUP", "", [2]string{"Digital Currency Address - ETH", a}), entry("DOE", "Jane",
			[2]string{"Digital Currency Address - USDT", b})),
			uk: "<Designations>" + c + "</Designations>", eu: "<export>" + d + "</export>",
			ofacFile: []string{a, b}, ukFile: []string{c}, summary: []string{"the same as their sources"}},
		{name: "one in and one out", ofac: sdnDoc("2", entry("GROUP", "", [2]string{"Digital Currency Address - ETH", a}), entry("NEW", "",
			[2]string{"Digital Currency Address - ETH", e})),
			uk: "<Designations>" + c + " and " + e + "</Designations>", eu: "<export>" + d + "</export>",
			ofacFile: []string{a, e}, ukFile: []string{c, e},
			summary: []string{"## OFAC", "- added `" + e + "`: NEW", "- removed `" + b + "`", "## UK",
				"- added `" + e + "`: found in the source on 2026-10-12"}, unchanged: []string{"## EU"}},
		{name: "checked only", ofac: sdnDoc("2", entry("GROUP", "", [2]string{"Digital Currency Address - ETH", a}), entry("NEW", "",
			[2]string{"Digital Currency Address - ETH", e})),
			uk: "<Designations>" + c + "</Designations>", eu: "<export>" + d + "</export>", check: true,
			ofacFile: []string{a, b}, ukFile: []string{c}, summary: []string{"## OFAC"}, unchanged: []string{"## UK"}},
		{name: "a sharp drop", ofac: sdnDoc("1", entry("GROUP", "", [2]string{"Digital Currency Address - ETH", a})),
			uk: "<Designations>" + c + "</Designations>", eu: "<export>" + d + "</export>", failed: "OFAC: the source lists 1 addresses against the file's 2",
			ofacFile: []string{a, b}, ukFile: []string{c}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/sdn.zip":
					w.Write(zipped(t, tc.ofac))
				case "/uk.xml":
					w.Write([]byte(tc.uk))
				case "/eu.xml":
					w.Write([]byte(tc.eu))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			dir := t.TempDir()
			for name, body := range map[string]string{
				"ofac.txt": "name: OFAC\nurl: " + srv.URL + "/sdn.zip\npublished: 2026-10-08\naddresses: 2\n" + a + " # GROUP\n" + b + " # DOE, Jane\n",
				"uk.txt":   "name: UK\nurl: " + srv.URL + "/uk.xml\npublished: 2026-10-08\naddresses: 1\n" + c + " # X0001 A DESIGNATION (Regime)\n",
				"eu.txt":   "name: EU\nurl: " + srv.URL + "/eu.xml\npublished: 2026-09-22\naddresses: 1\n" + d + " # EU.1.2 An entry\n",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			changes, err := run(context.Background(), dir, tc.check, now, &out)
			if tc.failed != "" {
				if err == nil || !strings.Contains(err.Error(), tc.failed) {
					t.Fatalf("%v; want a failure saying %q", err, tc.failed)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			ss, err := denylist.Read(dir)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(ss[0].Addresses, tc.ofacFile) || !slices.Equal(ss[1].Addresses, tc.ukFile) {
				t.Fatalf("the files hold OFAC %v and UK %v; want %v and %v", ss[0].Addresses, ss[1].Addresses, tc.ofacFile, tc.ukFile)
			}
			uk, _ := os.ReadFile(filepath.Join(dir, "uk.txt"))
			if !strings.Contains(string(uk), c+" # X0001 A DESIGNATION (Regime)") {
				t.Fatalf("the UK's note was lost:\n%s", uk)
			}
			if tc.failed != "" {
				return
			}
			md := markdown(changes)
			for _, want := range tc.summary {
				if !strings.Contains(md, want) {
					t.Errorf("the summary lacks %q:\n%s", want, md)
				}
			}
			for _, not := range tc.unchanged {
				if strings.Contains(md, not) {
					t.Errorf("the summary names %q, which did not change:\n%s", not, md)
				}
			}
		})
	}
}

// The status a check writes names the digest of the files in the directory, and while main's differ, the last
// day main's were vouched for, from the status the file held; a malformed status carries nothing, and a main
// digest that is no digest writes nothing. Made-up files.
func TestTheStatusNamesTheFilesAndWhenMainsWereLastTheSources(t *testing.T) {
	dir := t.TempDir()
	var files [][]byte
	for i, name := range denylist.Files {
		b := []byte(fmt.Sprintf("name: X%d\nurl: https://example.org/%d\npublished: 2026-10-01\naddresses: 1\n0x%040x\n", i, i, i+1))
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, b)
	}
	digest, other := denylist.Digest(files...), strings.Repeat("e", 64)
	path := filepath.Join(dir, "checked")
	read := func() string {
		b, _ := os.ReadFile(path)
		return string(b)
	}
	day := func(d int) time.Time { return time.Date(2026, 10, d, 6, 17, 0, 0, time.UTC) }
	for _, c := range []struct {
		held, main string
		on         time.Time
		want       string
	}{
		{"", digest, day(5), "checked 2026-10-05 " + digest + "\n"},
		{"checked 2026-10-05 " + other + "\n", other, day(12), "checked 2026-10-12 " + digest + " main 2026-10-05 " + other + "\n"},
		{"checked 2026-10-12 " + digest + " main 2026-10-05 " + other + "\n", other, day(19), "checked 2026-10-19 " + digest +
			" main 2026-10-05 " + other + "\n"},
		{"not a status\n", other, day(19), "checked 2026-10-19 " + digest + "\n"},
	} {
		if err := os.WriteFile(path, []byte(c.held), 0o644); err != nil {
			t.Fatal(err)
		}
		if c.held == "" {
			os.Remove(path)
		}
		if err := writeStatus(path, dir, c.main, c.on); err != nil || read() != c.want {
			t.Errorf("held %q, main %.8s: wrote %q (%v), want %q", c.held, c.main, read(), err, c.want)
		}
	}
	if err := writeStatus(path, dir, "main", day(26)); err == nil || read() != "checked 2026-10-19 "+digest+"\n" {
		t.Errorf("a main digest that is no digest: %v, the file %q", err, read())
	}
}

// A source that cannot be read, or answers with something other than its list, fails the whole run and leaves
// every file as it was, whatever the other sources give and in whichever list it happens: an HTTP error (one
// with the list in its body too), an empty answer, an error page answered with 200 (one that names an address
// the file holds, so only the form refuses it), an SDN_XML.ZIP that is not one or holds a second file, and a
// list after the first that drops to three of its five addresses. Every other source changes its list, so a
// file written before the failure would show. Made-up sources, addresses and pages.
func TestASourceThatIsNotItsListFailsTheRunAndWritesNothing(t *testing.T) {
	addr := func(n int) string { return fmt.Sprintf("0x%040x", n) }
	ofac, uk, eu, added := []string{addr(0x11), addr(0x12)}, []string{addr(0x31), addr(0x32), addr(0x33), addr(0x34), addr(0x35)},
		[]string{addr(0x41), addr(0x42), addr(0x43), addr(0x44), addr(0x45)}, addr(0x55)
	now := time.Date(2026, 10, 12, 6, 17, 0, 0, time.UTC)
	type answer struct {
		status int
		body   []byte
	}
	ok := func(body []byte) answer { return answer{http.StatusOK, body} }
	sdn := func(addrs ...string) string {
		var entries []string
		for i, a := range addrs {
			entries = append(entries, entry(fmt.Sprintf("GROUP %d", i), "", [2]string{"Digital Currency Address - ETH", a}))
		}
		return sdnDoc(fmt.Sprint(len(addrs)), entries...)
	}
	twoFiles := func() []byte {
		var buf bytes.Buffer
		z := zip.NewWriter(&buf)
		for _, name := range []string{"SDN.XML", "README.TXT"} {
			w, err := z.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			w.Write([]byte(sdn(ofac...)))
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	// Each source adds one address to its list.
	good := map[string]answer{
		"/sdn.zip": ok(zipped(t, sdn(append(slices.Clone(ofac), added)...))),
		"/uk.xml":  ok([]byte("<Designations>" + strings.Join(append(slices.Clone(uk), added), " ") + "</Designations>")),
		"/eu.xml":  ok([]byte("<export>" + strings.Join(append(slices.Clone(eu), added), " ") + "</export>")),
	}
	page := func(a string) []byte {
		return []byte("<!DOCTYPE html><html><head><title>Service unavailable</title></head><body><p>Try again later. " +
			"Last search: " + a + "</p></body></html>")
	}
	for _, tc := range []struct {
		name   string
		path   string
		answer answer
		says   string
	}{
		{"OFAC answers 404", "/sdn.zip", answer{http.StatusNotFound, []byte("404 page not found\n")}, "/sdn.zip: 404 Not Found"},
		{"OFAC answers 500 with its list", "/sdn.zip", answer{http.StatusInternalServerError, good["/sdn.zip"].body},
			"/sdn.zip: 500 Internal Server Error"},
		{"the UK answers 500 with its list", "/uk.xml", answer{http.StatusInternalServerError, good["/uk.xml"].body},
			"/uk.xml: 500 Internal Server Error"},
		{"the EU answers 503 with its list", "/eu.xml", answer{http.StatusServiceUnavailable, good["/eu.xml"].body},
			"/eu.xml: 503 Service Unavailable"},
		{"OFAC answers nothing", "/sdn.zip", ok(nil), "/sdn.zip: an empty answer"},
		{"the UK answers nothing", "/uk.xml", ok(nil), "/uk.xml: an empty answer"},
		{"the EU answers nothing", "/eu.xml", ok(nil), "/eu.xml: an empty answer"},
		{"OFAC answers an error page", "/sdn.zip", ok(page(ofac[0])), "SDN_XML.ZIP: zip: not a valid zip file"},
		{"the UK answers an error page", "/uk.xml", ok(page(uk[0])), "no <Designations near the start"},
		{"the EU answers an error page", "/eu.xml", ok(page(eu[0])), "no <export near the start"},
		{"OFAC's zip holds a second file", "/sdn.zip", ok(twoFiles()), "SDN_XML.ZIP holds 2 files, not SDN.XML alone"},
		{"the UK's list drops after OFAC's changed", "/uk.xml", ok([]byte("<Designations>" + strings.Join(uk[:3], " ") + "</Designations>")),
			"UK: the source lists 3 addresses against the file's 5"},
		{"the EU's list drops after the others changed", "/eu.xml", ok([]byte("<export>" + strings.Join(eu[:3], " ") + "</export>")),
			"EU: the source lists 3 addresses against the file's 5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ans, found := good[r.URL.Path]
				if r.URL.Path == tc.path {
					ans, found = tc.answer, true
				}
				if !found {
					http.NotFound(w, r)
					return
				}
				w.WriteHeader(ans.status)
				w.Write(ans.body)
			}))
			defer srv.Close()
			dir := t.TempDir()
			list := func(name, path string, addrs []string) []byte {
				return []byte("name: " + name + "\nurl: " + srv.URL + path + "\npublished: 2026-10-08\naddresses: " + fmt.Sprint(len(addrs)) + "\n" +
					strings.Join(addrs, " # an entry\n") + " # an entry\n")
			}
			before := map[string][]byte{"ofac.txt": list("OFAC", "/sdn.zip", ofac), "uk.txt": list("UK", "/uk.xml", uk),
				"eu.txt": list("EU", "/eu.xml", eu)}
			for name, body := range before {
				if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			changes, err := run(context.Background(), dir, false, now, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("%v, %d lists changed; want a failure saying %q", err, len(changes), tc.says)
			}
			for name, body := range before {
				if got, err := os.ReadFile(filepath.Join(dir, name)); err != nil || !bytes.Equal(got, body) {
					t.Errorf("%s was written:\n%s", name, got)
				}
			}
		})
	}
	// With every source answering its list, the same run writes all three: the failures above are the answers'.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ans, found := good[r.URL.Path]; found {
			w.Write(ans.body)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	dir := t.TempDir()
	for name, l := range map[string]struct {
		name, path string
		addrs      []string
	}{"ofac.txt": {"OFAC", "/sdn.zip", ofac}, "uk.txt": {"UK", "/uk.xml", uk}, "eu.txt": {"EU", "/eu.xml", eu}} {
		body := "name: " + l.name + "\nurl: " + srv.URL + l.path + "\npublished: 2026-10-08\naddresses: " + fmt.Sprint(len(l.addrs)) + "\n" +
			strings.Join(l.addrs, "\n") + "\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if changes, err := run(context.Background(), dir, false, now, io.Discard); err != nil || len(changes) != 3 {
		t.Fatalf("every source answering its list: %d lists changed, %v; want 3", len(changes), err)
	}
	ss, err := denylist.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range [][]string{ofac, uk, eu} {
		if want = append(slices.Clone(want), added); !slices.Equal(ss[i].Addresses, want) {
			t.Errorf("%s holds %v, want %v", ss[i].Name, ss[i].Addresses, want)
		}
	}
}
