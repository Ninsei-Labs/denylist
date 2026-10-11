// Command fetch writes the lists of this repository from their sources: ofac.txt from OFAC's list of
// Specially Designated Nationals, uk.txt and eu.txt from every address in EVM form the UK Sanctions List and
// the EU's consolidated list write in their free text, and each list read through OpenSanctions (see
// osDatasets) from the CryptoWallets its dataset export gives. Run from the repository's root. Each address keeps the
// note it had (the designation it comes from, kept by hand when a change is reviewed); a new one is noted
// with the day it was found. With -summary it writes, as Markdown, every address added and removed with its
// source, the body of the pull request the weekly workflow opens. With -check it writes nothing and fails
// when a list differs from its source. With -files it writes nothing and prints the list files' names, one
// line, which a workflow diffs and adds so a list added later is proposed like the rest. With -status it reads no source: it writes the status of today's check
// to the file named (denylist.Next), from the files in -dir, main's digest given with -main, and the status
// the file held.
//
// A source that cannot be read, reads in a form other than the one expected, or lists a fifth fewer
// addresses than the file holds fails the run: it is never taken for a list of fewer or no addresses.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Ninsei-Labs/denylist"
)

func main() {
	check := flag.Bool("check", false, "write nothing; fail when a list differs from its source")
	dir := flag.String("dir", ".", "the directory of the list files")
	summary := flag.String("summary", "", "write every change, as Markdown, to this file")
	status := flag.String("status", "", "write the status of today's check to this file, reading no source")
	mainDigest := flag.String("main", "", "with -status: the digest of main's list files")
	files := flag.Bool("files", false, "print the list files' names, one line, and write nothing")
	flag.Parse()
	if *files {
		fmt.Println(strings.Join(denylist.Files, " "))
		return
	}
	if *status != "" {
		if err := writeStatus(*status, *dir, *mainDigest, time.Now().UTC()); err != nil {
			fmt.Fprintln(os.Stderr, "fetch: "+err.Error())
			os.Exit(1)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	changes, err := run(ctx, *dir, *check, time.Now().UTC(), os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fetch: "+err.Error())
		os.Exit(1)
	}
	if *summary != "" {
		if err := os.WriteFile(*summary, []byte(markdown(changes)), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "fetch: "+err.Error())
			os.Exit(1)
		}
	}
	if len(changes) > 0 && *check {
		fmt.Println("the lists differ from their sources: run go run ./cmd/fetch and propose the change")
		os.Exit(1)
	}
}

// writeStatus writes the status of a check on the day of now to path: the digest of the Core list files in
// dir, as the sources gave them, and while main's (mainDigest) differ, the last day those were vouched for,
// carried from the status path held. A status that cannot be read carries nothing.
func writeStatus(path, dir, mainDigest string, now time.Time) error {
	if len(mainDigest) != 64 || strings.Trim(mainDigest, "0123456789abcdef") != "" {
		return fmt.Errorf("-main %q is not a digest", mainDigest)
	}
	var files [][]byte
	for _, name := range denylist.Core {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		files = append(files, b)
	}
	var prev denylist.Status
	if b, err := os.ReadFile(path); err == nil {
		prev, _ = denylist.ParseChecked(b)
	}
	day := now.UTC().Truncate(24 * time.Hour)
	return os.WriteFile(path, []byte(denylist.Next(prev, day, denylist.Digest(files...), mainDigest).String()+"\n"), 0o644)
}

// change is what a source holds now against its file: the addresses added, with their notes, and removed.
type change struct {
	name           string
	added, removed []string
	notes          map[string]string
}

// minShare is the least share of a file's addresses a source may list: a sharper drop is a source that
// changed its form, or a mistake, until a person says otherwise.
const minShare = 0.8

func run(ctx context.Context, dir string, check bool, now time.Time, out io.Writer) ([]change, error) {
	have, err := denylist.Read(dir)
	if err != nil {
		return nil, err
	}
	var changes []change
	for i, s := range have {
		path := filepath.Join(dir, denylist.Files[i])
		old, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		notes := notesOf(old)
		read, published, err := readSource(ctx, s)
		if err != nil {
			return nil, err
		}
		if float64(len(read)) < minShare*float64(len(s.Addresses)) {
			return nil, fmt.Errorf("%s: the source lists %d addresses against the file's %d: a drop this sharp is checked by hand",
				s.Name, len(read), len(s.Addresses))
		}
		c := change{name: s.Name, notes: map[string]string{}}
		c.added, c.removed = diff(s.Addresses, slices.Sorted(maps(read)))
		for _, a := range c.added {
			c.notes[a] = read[a]
			if c.notes[a] == "" {
				c.notes[a] = "found in the source on " + now.Format(time.DateOnly)
			}
		}
		if len(c.added)+len(c.removed) == 0 {
			fmt.Fprintf(out, "%s: the same %d addresses\n", s.Name, len(s.Addresses))
			continue
		}
		changes = append(changes, c)
		fmt.Fprintf(out, "%s: %d added, %d removed\n", s.Name, len(c.added), len(c.removed))
		if check {
			continue
		}
		for a, n := range read {
			if n == "" {
				read[a] = notes[a]
			}
			if read[a] == "" {
				read[a] = c.notes[a]
			}
		}
		if published == "" {
			published = now.Format(time.DateOnly)
		}
		if err := os.WriteFile(path, file(s, published, read), 0o644); err != nil {
			return nil, err
		}
	}
	return changes, nil
}

// readSource reads a list's source: each address in EVM form with its note (OFAC's names the entries that list
// it; the UK's and the EU's give none, so a file's own notes stay), and the date the source gives itself, ""
// when it gives none.
func readSource(ctx context.Context, s denylist.Source) (map[string]string, string, error) {
	switch s.Name {
	case "OFAC":
		zipped, err := get(ctx, s.URL)
		if err != nil {
			return nil, "", err
		}
		doc, err := unzipSDN(zipped)
		if err != nil {
			return nil, "", err
		}
		sdn, err := readSDN(bytes.NewReader(doc))
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", s.URL, err)
		}
		read := map[string]string{}
		for a, names := range sdn.names {
			read[a] = strings.Join(names, "; ")
		}
		return read, sdn.published, nil
	case "UK", "EU":
		b, err := get(ctx, s.URL)
		if err != nil {
			return nil, "", err
		}
		if !bytes.Contains(b[:min(len(b), 4096)], []byte(rootOf[s.Name])) {
			return nil, "", fmt.Errorf("%s: no %s near the start: not the file it was", s.URL, rootOf[s.Name])
		}
		found := evmIn(b)
		if len(found) == 0 {
			return nil, "", fmt.Errorf("%s: no address in EVM form at all: its format may have changed", s.URL)
		}
		read := map[string]string{}
		for _, a := range found {
			read[a] = ""
		}
		return read, "", nil
	}
	if d, ok := osDatasets[s.Name]; ok {
		return readOpenSanctions(ctx, d)
	}
	return nil, "", fmt.Errorf("no source named %s", s.Name)
}

// osBase is where OpenSanctions' latest dataset exports live. A variable, so a test can serve its own.
var osBase = "https://data.opensanctions.org/datasets/latest/"

// osDataset is one list read through OpenSanctions, which normalises the official publication into a single
// export: the dataset's id, and the file's opening comment.
type osDataset struct {
	id     string // the OpenSanctions dataset id, under osBase
	header string // the file's opening comment: what the list is and its source's terms
}

// osDatasets are the lists read that way, by their source name. Adding one is one entry here and one line in
// denylist.Files.
var osDatasets = map[string]osDataset{}

// osRoot is how OpenSanctions' entity export opens: a page answered with 200 that is not it has no "schema"
// near the start.
const osRoot = `"schema"`

// readOpenSanctions reads a list from OpenSanctions' export of its dataset (d.id): the dataset's index for
// the day it last changed, and its entities for every CryptoWallet whose publicKey is an address in EVM
// form, lower-cased, each with the target that holds it as its note.
func readOpenSanctions(ctx context.Context, d osDataset) (map[string]string, string, error) {
	url := osBase + d.id + "/index.json"
	idx, err := get(ctx, url)
	if err != nil {
		return nil, "", err
	}
	published, err := exportDay(idx)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", url, err)
	}
	url = osBase + d.id + "/entities.ftm.json"
	b, err := get(ctx, url)
	if err != nil {
		return nil, "", err
	}
	if !bytes.Contains(b[:min(len(b), 4096)], []byte(osRoot)) {
		return nil, "", fmt.Errorf("%s: no %s near the start: not the file it was", url, osRoot)
	}
	read, err := readWallets(b)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", url, err)
	}
	if len(read) == 0 {
		return nil, "", fmt.Errorf("%s: no address in EVM form at all: its format may have changed", url)
	}
	return read, published, nil
}

// exportDay is the day a dataset last changed, from its index: the export read was written from the source
// as of then, not the day the check ran.
func exportDay(b []byte) (string, error) {
	var idx struct {
		LastChange string `json:"last_change"`
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		return "", err
	}
	if idx.LastChange == "" {
		return "", errors.New("no last_change: the index is not the one expected")
	}
	// OpenSanctions writes the stamp without a zone; take one with an offset too.
	day, err := time.Parse(time.RFC3339, idx.LastChange)
	if err != nil {
		day, err = time.Parse("2006-01-02T15:04:05", idx.LastChange)
	}
	if err != nil {
		return "", fmt.Errorf("last_change %q: %w", idx.LastChange, err)
	}
	return day.Format(time.DateOnly), nil
}

// wallet is the part of an OpenSanctions entity readWallets uses.
type wallet struct {
	ID         string              `json:"id"`
	Caption    string              `json:"caption"`
	Schema     string              `json:"schema"`
	Referents  []string            `json:"referents"`
	Properties map[string][]string `json:"properties"`
}

// readWallets reads an OpenSanctions export: every CryptoWallet whose publicKey is an address in EVM form,
// lower-cased, each with the caption of the target that holds it (its holder, as the export links them) as
// its note. A target with no name of its own, and a wallet no target holds, carry none: the note is left
// off, never invented.
func readWallets(b []byte) (map[string]string, error) {
	var ents []wallet
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e wallet
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, err
		}
		ents = append(ents, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// names are each target's caption, by its id and each of its referents, so a wallet's holder can be named.
	names := map[string]string{}
	for _, e := range ents {
		n := targetName(e)
		if n == "" {
			continue
		}
		names[e.ID] = n
		for _, r := range e.Referents {
			names[r] = n
		}
	}
	read := map[string]string{}
	for _, e := range ents {
		if e.Schema != "CryptoWallet" {
			continue
		}
		var held []string
		for _, h := range e.Properties["holder"] {
			if n := names[h]; n != "" && !slices.Contains(held, n) {
				held = append(held, n)
			}
		}
		for _, k := range e.Properties["publicKey"] {
			a := strings.ToLower(strings.TrimSpace(k))
			if !evmForm.MatchString(a) {
				continue
			}
			if note := strings.Join(held, "; "); note != "" && read[a] == "" {
				read[a] = note
			} else if _, ok := read[a]; !ok {
				read[a] = ""
			}
		}
	}
	return read, nil
}

// targetName is a target's name as its caption gives it, "" when it has none: OpenSanctions writes a
// designation without a name with only its schema as a caption.
func targetName(e wallet) string {
	c := strings.Join(strings.Fields(e.Caption), " ")
	if c == "" || c == e.Schema {
		return ""
	}
	return c
}

func maps(m map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// notesOf is each address's note in a list file, the text after its #.
func notesOf(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "0x") {
			continue
		}
		a, note, _ := strings.Cut(line, "#")
		out[strings.TrimSpace(a)] = strings.TrimSpace(note)
	}
	return out
}

// head is a list's opening comment: the three written here, or the one a list read through OpenSanctions
// carries.
func head(name string) string {
	if d, ok := osDatasets[name]; ok {
		return d.header
	}
	return header[name]
}

// header is each list file's opening comment: what the list is, how it is written, and its source's terms.
var header = map[string]string{
	"OFAC": `# OFAC's list of Specially Designated Nationals: every "Digital Currency Address" of any coin whose value
# is an address in EVM form, lower-cased, with the entries that list it. Written by go run ./cmd/fetch from
# the file below; do not edit by hand. Source: U.S. Department of the Treasury, Office of Foreign Assets
# Control; a work of the US government, in the public domain.
`,
	"UK": `# The UK Sanctions List (FCDO), which binds operators in the UK and UK persons anywhere: the addresses in
# EVM form its designations give. The file writes them only in free text (OtherInformation), several ways;
# go run ./cmd/fetch finds them, and each note names the designation it comes from, kept by hand.
# Contains public sector information licensed under the Open Government Licence v3.0.
`,
	"EU": `# The EU's consolidated list of financial sanctions, which binds operators in the EU, EU nationals
# anywhere and business done in the EU: the addresses in EVM form its entries give. The file writes them
# only in free text (remark); go run ./cmd/fetch finds them, and each note names the entry it comes from,
# kept by hand. Source: European Commission, Consolidated list of persons, groups and entities subject to EU
# financial sanctions; reused under the Commission's reuse policy, with the source acknowledged.
`,
}

// file is a list file as denylist.Parse reads it: the header, then each address with its note.
func file(s denylist.Source, published string, read map[string]string) []byte {
	var b strings.Builder
	b.WriteString(head(s.Name))
	fmt.Fprintf(&b, "name: %s\nurl: %s\npublished: %s\naddresses: %d\n\n", s.Name, s.URL, published, len(read))
	for _, a := range slices.Sorted(maps(read)) {
		if read[a] == "" {
			fmt.Fprintln(&b, a)
			continue
		}
		fmt.Fprintf(&b, "%s # %s\n", a, read[a])
	}
	return []byte(b.String())
}

// markdown is every change as a pull request's body says it.
func markdown(changes []change) string {
	if len(changes) == 0 {
		return "The lists are the same as their sources.\n"
	}
	var b strings.Builder
	b.WriteString("The lists as their sources give them now. Review each address added (its note says where it\n")
	b.WriteString("comes from; correct a note by hand where it should name the designation) and each removed before\n")
	b.WriteString("merging: readers use the lists of main as they are.\n")
	for _, c := range changes {
		fmt.Fprintf(&b, "\n## %s\n\n", c.name)
		for _, a := range c.added {
			fmt.Fprintf(&b, "- added `%s`: %s\n", a, c.notes[a])
		}
		for _, a := range c.removed {
			fmt.Fprintf(&b, "- removed `%s`\n", a)
		}
	}
	return b.String()
}

// rootOf is how each file opens, so that an error page answered with 200 is not read as a list.
var rootOf = map[string]string{"UK": "<Designations", "EU": "<export"}

// diff is what read holds that have does not, and what have holds that read does not.
func diff(have, read []string) (added, removed []string) {
	for _, a := range read {
		if !slices.Contains(have, a) {
			added = append(added, a)
		}
	}
	for _, a := range have {
		if !slices.Contains(read, a) {
			removed = append(removed, a)
		}
	}
	return added, removed
}

// get reads a source whole. OFAC answers an unknown file with 200 and nothing, so an empty body is an error.
func get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// OFAC refuses a request without one.
	req.Header.Set("User-Agent", "Ninsei-Labs denylist fetch")
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err == nil && len(b) == 0 {
		err = errors.New("an empty answer")
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	return b, nil
}

// unzipSDN is the one member of OFAC's SDN_XML.ZIP, SDN.XML.
func unzipSDN(b []byte) ([]byte, error) {
	z, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, fmt.Errorf("SDN_XML.ZIP: %w", err)
	}
	if len(z.File) != 1 || z.File[0].Name != "SDN.XML" {
		return nil, fmt.Errorf("SDN_XML.ZIP holds %d files, not SDN.XML alone", len(z.File))
	}
	f, err := z.File[0].Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// sdnNamespace is the namespace of SDN.XML since 2024-05-07. Another one is another format, unknown.
const sdnNamespace = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML"

// sdnList is what fetch takes of SDN.XML: the publication's date, and each address in EVM form with the
// names of the entries that list it.
type sdnList struct {
	published string
	names     map[string][]string
}

// readSDN reads SDN.XML to its end: every "Digital Currency Address" of any coin whose value is an address
// in EVM form, lower-cased (OFAC tags some only USDT, USDC, ARB or BSC; the node's check is by address).
// The publication must say its date and count its entries, and the count must be the entries read; at least
// one digital currency address must be there, of any chain. Otherwise the file is not the one expected.
func readSDN(r io.Reader) (sdnList, error) {
	l := sdnList{names: map[string][]string{}}
	d := xml.NewDecoder(r)
	entries, count, digital := 0, -1, 0
	root := false
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return sdnList{}, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch {
		case !root:
			if se.Name.Local != "sdnList" || se.Name.Space != sdnNamespace {
				return sdnList{}, fmt.Errorf("the document is %s in %q, not sdnList in %s", se.Name.Local, se.Name.Space, sdnNamespace)
			}
			root = true
		case se.Name.Local == "publshInformation": // sic
			var p struct {
				Date  string `xml:"Publish_Date"`
				Count string `xml:"Record_Count"`
			}
			if err := d.DecodeElement(&p, &se); err != nil {
				return sdnList{}, err
			}
			day, err := time.Parse("01/02/2006", strings.TrimSpace(p.Date))
			if err != nil {
				return sdnList{}, fmt.Errorf("the publication's date %q: %w", p.Date, err)
			}
			if count, err = strconv.Atoi(strings.TrimSpace(p.Count)); err != nil {
				return sdnList{}, fmt.Errorf("the publication's count %q: %w", p.Count, err)
			}
			l.published = day.Format(time.DateOnly)
		case se.Name.Local == "sdnEntry":
			var e struct {
				First string `xml:"firstName"`
				Last  string `xml:"lastName"`
				IDs   []struct {
					Type   string `xml:"idType"`
					Number string `xml:"idNumber"`
				} `xml:"idList>id"`
			}
			if err := d.DecodeElement(&e, &se); err != nil {
				return sdnList{}, err
			}
			entries++
			name := strings.Join(strings.Fields(e.Last), " ")
			if f := strings.Join(strings.Fields(e.First), " "); f != "" {
				name += ", " + f
			}
			for _, id := range e.IDs {
				if !strings.HasPrefix(id.Type, "Digital Currency Address") {
					continue
				}
				digital++
				a := strings.ToLower(strings.TrimSpace(id.Number))
				if evmForm.MatchString(a) && !slices.Contains(l.names[a], name) {
					l.names[a] = append(l.names[a], name)
				}
			}
		}
	}
	switch {
	case !root:
		return sdnList{}, errors.New("no document")
	case l.published == "" || count < 0:
		return sdnList{}, errors.New("no publication date or count")
	case count != entries:
		return sdnList{}, fmt.Errorf("the publication counts %d entries and the file holds %d", count, entries)
	case digital == 0:
		return sdnList{}, errors.New("no digital currency address of any chain: the format may have changed")
	case len(l.names) == 0:
		return sdnList{}, errors.New("no address in EVM form")
	}
	return l, nil
}

var (
	evmForm = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
	evmText = regexp.MustCompile(`0x[0-9a-fA-F]{40}`)
)

// evmIn is every address in EVM form written anywhere in a file, lower-cased, sorted, each once: the UK and
// EU lists give them in free text, several ways. A longer run of hex digits (a transaction hash) is none.
func evmIn(b []byte) []string {
	var out []string
	for _, m := range evmText.FindAllIndex(b, -1) {
		if m[0] > 0 && word(b[m[0]-1]) || m[1] < len(b) && word(b[m[1]]) {
			continue
		}
		out = append(out, strings.ToLower(string(b[m[0]:m[1]])))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func word(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
