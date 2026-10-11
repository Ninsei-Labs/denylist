package main

import (
	"archive/zip"
	"bytes"
	"context"
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
