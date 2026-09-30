// domcheck: fast domain availability checker.
//
// Pipeline per domain:
//  1. DNS NS lookup (~10-30ms). A delegation in the TLD zone means taken.
//  2. Otherwise ask the registry: RDAP (404 = available, 200 = taken),
//     falling back to WHOIS for TLDs without RDAP.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	bootstrapURL = "https://data.iana.org/rdap/dns.json"
	perRegistry  = 4 // concurrent RDAP requests per registry; bursts beyond this trigger 429s
)

// RDAP servers that exist but are missing from the IANA bootstrap.
var rdapExtra = map[string]string{
	"ch": "https://rdap.nic.ch/",
	"li": "https://rdap.nic.ch/",
	"io": "https://rdap.identitydigital.services/rdap/",
}

var (
	domainRe     = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$`)
	whoisFreeRe  = regexp.MustCompile(`(?i)no match|not found|no entries found|no data found|no object found|status:\s*(free|available)|is available|not registered`)
	whoisTakenRe = regexp.MustCompile(`(?i)registrar|creat(ed|ion)|expir|nserver|name ?server|status:`)
)

type status int

const (
	unknown status = iota
	available
	taken
)

type result struct {
	domain string
	st     status
	via    string
	dur    time.Duration
}

var (
	timeout    time.Duration
	httpClient *http.Client
	dnsServers = []string{"1.1.1.1:53", "8.8.8.8:53", "1.0.0.1:53", "8.8.4.4:53"}
	dnsNext    atomic.Uint32
	resolver   = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, dnsServers[dnsNext.Add(1)%uint32(len(dnsServers))])
	}}
	bootstrap  = sync.OnceValue(loadBootstrap)
	whoisDisk  = sync.OnceValue(loadWhoisCache)
	whoisByTLD sync.Map // tld -> func() string
	registries sync.Map // RDAP base URL -> *registry
)

type registry struct {
	sem       chan struct{}
	throttled atomic.Bool // still rate-limited after retries: fail fast for the rest of the run
}

type whoisCache struct {
	mu    sync.Mutex
	m     map[string]string
	dirty bool
}

func main() {
	tlds := flag.String("t", "com,net,org,io,ai,co,dev,app,ch,de,xyz,me", "TLDs to try for bare names (comma-separated)")
	onlyFree := flag.Bool("a", false, "only show available domains")
	conc := flag.Int("c", 64, "max concurrent checks")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "per-request timeout")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: domcheck [flags] name|domain ...   (or pipe one per line on stdin)\n\n"+
			"  domcheck acme               acme.com, acme.io, ... across -t TLDs\n"+
			"  domcheck acme.ch foo.dev    exact domains\n"+
			"  cat names.txt | domcheck -a -t com\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = *conc
	httpClient = &http.Client{Timeout: timeout, Transport: tr}

	inputs := flag.Args()
	if len(inputs) == 0 {
		if fi, _ := os.Stdin.Stat(); fi.Mode()&os.ModeCharDevice != 0 {
			flag.Usage()
			os.Exit(2)
		}
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			inputs = append(inputs, strings.Fields(sc.Text())...)
		}
	}
	domains := expand(inputs, strings.Split(*tlds, ","))
	if len(domains) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	// Resolve WHOIS servers for RDAP-less TLDs while the DNS phase runs.
	seenTLD := map[string]bool{}
	for _, d := range domains {
		if tld := d[strings.LastIndexByte(d, '.')+1:]; !seenTLD[tld] {
			seenTLD[tld] = true
			go func() {
				if rdapBase(tld) == "" {
					whoisServer(tld)
				}
			}()
		}
	}

	fi, _ := os.Stdout.Stat()
	tty := fi.Mode()&os.ModeCharDevice != 0
	start := time.Now()

	// Check concurrently, but print in input order as soon as each prefix is done.
	results := make([]*result, len(domains))
	done := make(chan int)
	sem := make(chan struct{}, *conc)
	for i, d := range domains {
		go func() {
			sem <- struct{}{}
			r := check(d)
			<-sem
			results[i] = &r
			done <- i
		}()
	}
	nFree, next := 0, 0
	for range domains {
		<-done
		for next < len(results) && results[next] != nil {
			r := results[next]
			if r.st == available {
				nFree++
			}
			if !*onlyFree || r.st == available {
				printResult(r, tty)
			}
			next++
		}
	}
	saveWhoisCache()
	if tty {
		fmt.Fprintf(os.Stderr, "\033[2m%d checked · %d available · %s\033[0m\n", len(domains), nFree, time.Since(start).Round(time.Millisecond))
	}
}

func expand(inputs, tlds []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(d string) {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	for _, in := range inputs {
		in = strings.ToLower(strings.TrimSpace(in))
		in = strings.TrimPrefix(strings.TrimPrefix(in, "https://"), "http://")
		in = strings.TrimSuffix(strings.SplitN(in, "/", 2)[0], ".")
		if in == "" {
			continue
		}
		if strings.Contains(in, ".") {
			add(in)
			continue
		}
		for _, t := range tlds {
			if t = strings.Trim(strings.TrimSpace(t), "."); t != "" {
				add(in + "." + t)
			}
		}
	}
	return out
}

func printResult(r *result, tty bool) {
	if !tty {
		fmt.Printf("%s\t%s\t%s\n", r.domain, [...]string{"unknown", "available", "taken"}[r.st], r.via)
		return
	}
	icon := [...]string{"\033[33m?", "\033[32m✓", "\033[31m✗"}[r.st]
	label := [...]string{"unknown  ", "available", "taken    "}[r.st]
	fmt.Printf("%s %-32s %s\033[0m  \033[2m%-6s %5dms\033[0m\n", icon, r.domain, label, r.via, r.dur.Milliseconds())
}

func check(d string) result {
	start := time.Now()
	st, via := checkDomain(d)
	return result{d, st, via, time.Since(start)}
}

func checkDomain(d string) (status, string) {
	if !domainRe.MatchString(d) {
		return unknown, "invalid"
	}
	if delegated(d) {
		return taken, "dns"
	}

	tld := d[strings.LastIndexByte(d, '.')+1:]
	if base := rdapBase(tld); base != "" {
		st, err := rdap(base, d)
		if err == nil {
			return st, "rdap"
		}
		if srv := whoisServer(tld); srv != "" {
			if st, werr := whois(srv, d); werr == nil {
				return st, "whois"
			}
		}
		return unknown, "rdap: " + err.Error()
	}
	if srv := whoisServer(tld); srv != "" {
		st, err := whois(srv, d)
		if err != nil {
			return unknown, "whois: " + err.Error()
		}
		return st, "whois"
	}
	return unknown, "no registry"
}

func registryFor(base string) *registry {
	if r, ok := registries.Load(base); ok {
		return r.(*registry)
	}
	r := &registry{sem: make(chan struct{}, perRegistry)}
	v, _ := registries.LoadOrStore(base, r)
	return v.(*registry)
}

// delegated races two resolvers (round-robin picks different servers) and takes
// the first answer, so a lost UDP packet doesn't stall on the resolver's retry timeout.
func delegated(d string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	answers := make(chan bool, 2)
	for range 2 {
		go func() {
			ns, err := resolver.LookupNS(ctx, d+".") // FQDN: skip resolv.conf search domains
			answers <- err == nil && len(ns) > 0
		}()
	}
	return <-answers
}

func rdap(base, d string) (status, error) {
	reg := registryFor(base)
	url := strings.TrimSuffix(base, "/") + "/domain/" + d
	for attempt := 0; ; attempt++ {
		if reg.throttled.Load() {
			return unknown, errors.New("rate-limited")
		}
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Accept", "application/rdap+json")
		reg.sem <- struct{}{}
		resp, err := httpClient.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		<-reg.sem
		switch {
		case err != nil:
			return unknown, errors.New("unreachable")
		case resp.StatusCode == 200:
			return taken, nil
		case resp.StatusCode == 404:
			return available, nil
		case resp.StatusCode == 429 && attempt == 2:
			reg.throttled.Store(true)
			return unknown, errors.New("rate-limited")
		case resp.StatusCode == 429 || resp.StatusCode >= 500 && attempt < 2:
			wait := 300 * time.Millisecond << (2 * attempt) // 300ms, 1.2s
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s <= 2 {
				wait = time.Duration(s) * time.Second
			}
			time.Sleep(wait + rand.N(wait/2))
		default:
			return unknown, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
	}
}

func whois(server, query string) (status, error) {
	conn, err := net.DialTimeout("tcp", server+":43", timeout)
	if err != nil {
		return unknown, errors.New("unreachable")
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return unknown, err
	}
	b, err := io.ReadAll(conn)
	if err != nil && len(b) == 0 {
		return unknown, errors.New("no response")
	}
	switch s := string(b); {
	case whoisFreeRe.MatchString(s):
		return available, nil
	case whoisTakenRe.MatchString(s):
		return taken, nil
	}
	return unknown, errors.New("unrecognized reply (rate-limited?)")
}

// whoisServer finds a TLD's WHOIS server via IANA once, cached on disk.
func whoisServer(tld string) string {
	f, _ := whoisByTLD.LoadOrStore(tld, sync.OnceValue(func() string {
		c := whoisDisk()
		c.mu.Lock()
		srv, ok := c.m[tld]
		c.mu.Unlock()
		if ok {
			return srv
		}
		if srv = ianaWhois(tld); srv != "" {
			c.mu.Lock()
			c.m[tld], c.dirty = srv, true
			c.mu.Unlock()
		}
		return srv
	}))
	return f.(func() string)()
}

func ianaWhois(tld string) string {
	conn, err := net.DialTimeout("tcp", "whois.iana.org:43", timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	io.WriteString(conn, tld+"\r\n")
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "whois:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func loadWhoisCache() *whoisCache {
	c := &whoisCache{m: map[string]string{}}
	if data, err := os.ReadFile(cachePath("whois-servers.json")); err == nil {
		json.Unmarshal(data, &c.m)
	}
	return c
}

func saveWhoisCache() {
	c := whoisDisk()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dirty {
		data, _ := json.Marshal(c.m)
		writeCache("whois-servers.json", data)
	}
}

func cachePath(name string) string {
	dir, _ := os.UserCacheDir()
	return filepath.Join(dir, "domcheck", name)
}

func writeCache(name string, data []byte) {
	path := cachePath(name)
	os.MkdirAll(filepath.Dir(path), 0o755)
	os.WriteFile(path, data, 0o644)
}

func rdapBase(tld string) string {
	if b, ok := rdapExtra[tld]; ok {
		return b
	}
	return bootstrap()[tld]
}

// loadBootstrap returns the IANA TLD -> RDAP base URL map, cached on disk for a week.
func loadBootstrap() map[string]string {
	path := cachePath("rdap-dns.json")
	data, err := os.ReadFile(path)
	if fi, statErr := os.Stat(path); err != nil || statErr != nil || time.Since(fi.ModTime()) > 7*24*time.Hour {
		if fresh, ferr := fetch(bootstrapURL); ferr == nil {
			data = fresh
			writeCache("rdap-dns.json", fresh)
		}
	}
	var bs struct {
		Services [][][]string `json:"services"`
	}
	m := map[string]string{}
	if json.Unmarshal(data, &bs) != nil {
		return m
	}
	for _, svc := range bs.Services {
		if len(svc) == 2 && len(svc[1]) > 0 {
			for _, tld := range svc[0] {
				m[tld] = svc[1][0]
			}
		}
	}
	return m
}

func fetch(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
