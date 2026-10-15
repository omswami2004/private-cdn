package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------- jobs ----------

type job struct {
	ID     string    `json:"id"`
	URL    string    `json:"url"`
	Folder string    `json:"folder"`
	Status string    `json:"status"` // queued, downloading, converting, done, error
	Name   string    `json:"name"`
	Done   int64     `json:"done"`
	Total  int64     `json:"total"`
	Error  string    `json:"error,omitempty"`
	Link   string    `json:"link,omitempty"`
	Added  time.Time `json:"added"`
	// Convert makes videos (or videos inside a zip) browser-playable after
	// the download; Note says what that did.
	Convert bool   `json:"convert"`
	Note    string `json:"note,omitempty"`
}

type fetcher struct {
	s      *server
	client *http.Client
	sem    chan struct{}

	mu   sync.Mutex
	jobs []*job
}

const maxJobsKept = 200

func newFetcher(s *server, parallel int) *fetcher {
	dialer := &net.Dialer{Timeout: 20 * time.Second, Control: refusePrivate}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: 90 * time.Second,
		MaxIdleConns:          10,
		IdleConnTimeout:       60 * time.Second,
	}
	return &fetcher{
		s:   s,
		sem: make(chan struct{}, parallel),
		client: &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return errors.New("redirect to a non-http link")
			}
			return nil
		}},
	}
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// refusePrivate stops links (and their redirects) from reaching this server's
// own services or the local network.
func refusePrivate(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		cgnat.Contains(ip) {
		return fmt.Errorf("refusing to connect to non-public address %s", host)
	}
	return nil
}

func (f *fetcher) add(rawURL, folder string, convert bool) *job {
	id := make([]byte, 5)
	rand.Read(id)
	j := &job{ID: hex.EncodeToString(id), URL: rawURL, Folder: folder, Status: "queued", Added: time.Now(), Convert: convert}
	f.mu.Lock()
	f.jobs = append(f.jobs, j)
	if len(f.jobs) > maxJobsKept {
		f.jobs = f.jobs[len(f.jobs)-maxJobsKept:]
	}
	f.mu.Unlock()
	go f.run(j)
	return j
}

func (f *fetcher) update(j *job, fn func(*job)) {
	f.mu.Lock()
	fn(j)
	f.mu.Unlock()
}

func (f *fetcher) snapshot() []job {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]job, 0, len(f.jobs))
	for i := len(f.jobs) - 1; i >= 0; i-- {
		out = append(out, *f.jobs[i])
	}
	return out
}

// clearFinished drops done and failed jobs from the list, keeping the ones
// still queued or running.
func (f *fetcher) clearFinished() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := f.jobs[:0]
	for _, j := range f.jobs {
		if j.Status != "done" && j.Status != "error" {
			kept = append(kept, j)
		}
	}
	n := len(f.jobs) - len(kept)
	clear(f.jobs[len(kept):])
	f.jobs = kept
	return n
}

func (f *fetcher) run(j *job) {
	f.sem <- struct{}{}
	defer func() { <-f.sem }()
	f.update(j, func(j *job) { j.Status = "downloading" })

	dest, err := f.download(j)
	if err != nil {
		log.Printf("fetch %s: %v", j.URL, err)
		f.update(j, func(j *job) { j.Status, j.Error = "error", err.Error() })
		return
	}
	note := ""
	if j.Convert && (isZip(dest) || isVideoName(dest)) {
		f.update(j, func(j *job) { j.Status, j.Name = "converting", filepath.Base(dest) })
		dest, note = f.convert(dest)
	}
	rel := f.s.relOf(dest)
	link := f.s.shares.url(f.s.cfg.PublicURL, rel)
	log.Printf("fetch %s -> %s %s", j.URL, rel, note)
	f.update(j, func(j *job) { j.Status, j.Name, j.Link, j.Note = "done", filepath.Base(dest), link, note })
}

// convert runs makePlayable; a failed conversion keeps the original download.
func (f *fetcher) convert(file string) (string, string) {
	if !haveFFmpeg() {
		return file, "not converted: " + errNoFFmpeg.Error()
	}
	newPath, note, err := makePlayable(context.Background(), file)
	if err != nil {
		log.Printf("convert %s: %v", f.s.relOf(file), err)
		return file, "not converted, original kept: " + err.Error()
	}
	return newPath, note
}

// ---------- link types ----------

var driveIDPatterns = []*regexp.Regexp{
	regexp.MustCompile(`/file/d/([A-Za-z0-9_-]{10,})`),
	regexp.MustCompile(`[?&]id=([A-Za-z0-9_-]{10,})`),
}

func driveID(u *url.URL) string {
	if u.Host != "drive.google.com" && u.Host != "docs.google.com" && u.Host != "drive.usercontent.google.com" {
		return ""
	}
	for _, re := range driveIDPatterns {
		if m := re.FindStringSubmatch(u.String()); m != nil {
			return m[1]
		}
	}
	return ""
}

// directURL rewrites share-page links into direct downloads.
func directURL(u *url.URL) (string, bool) {
	if id := driveID(u); id != "" {
		return "https://drive.usercontent.google.com/download?export=download&confirm=t&id=" + url.QueryEscape(id), true
	}
	if strings.HasSuffix(u.Host, "dropbox.com") {
		q := u.Query()
		q.Del("dl")
		q.Set("dl", "1")
		u.RawQuery = q.Encode()
	}
	return u.String(), false
}

var (
	formAction  = regexp.MustCompile(`(?is)<form[^>]+id="download-form"[^>]+action="([^"]+)"`)
	hiddenInput = regexp.MustCompile(`(?is)<input[^>]+type="hidden"[^>]+name="([^"]+)"[^>]+value="([^"]*)"`)
)

// driveConfirm follows Google Drive's "can't scan this file for viruses" page.
func driveConfirm(page string) (string, bool) {
	m := formAction.FindStringSubmatch(page)
	if m == nil {
		return "", false
	}
	u, err := url.Parse(html.UnescapeString(m[1]))
	if err != nil {
		return "", false
	}
	q := u.Query()
	for _, in := range hiddenInput.FindAllStringSubmatch(page, -1) {
		q.Set(html.UnescapeString(in[1]), html.UnescapeString(in[2]))
	}
	u.RawQuery = q.Encode()
	return u.String(), true
}

func (f *fetcher) get(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux aarch64) private-cdn-fetch")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("server answered %s", resp.Status)
	}
	return resp, nil
}

func isHTML(resp *http.Response) bool {
	return strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html")
}

func (f *fetcher) download(j *job) (string, error) {
	ctx := context.Background()
	u, err := url.Parse(j.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("not an http(s) link")
	}
	src, isDrive := directURL(u)
	resp, err := f.get(ctx, src)
	if err != nil {
		return "", err
	}
	if isDrive && isHTML(resp) {
		page, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		next, ok := driveConfirm(string(page))
		if !ok {
			return "", errors.New("Google Drive did not return the file: share it as \"Anyone with the link\" (folders are not supported)")
		}
		if resp, err = f.get(ctx, next); err != nil {
			return "", err
		}
		if isHTML(resp) {
			resp.Body.Close()
			return "", errors.New("Google Drive refused the download (quota exceeded or not public)")
		}
	}
	defer resp.Body.Close()

	name := nameFromResponse(resp)
	dir, err := f.s.ensureDir(j.Folder)
	if err != nil {
		return "", err
	}
	f.update(j, func(j *job) { j.Name, j.Total = name, resp.ContentLength })

	pr := &progressReader{r: resp.Body, onRead: func(n int64) {
		f.update(j, func(j *job) { j.Done += n })
	}}
	return writeAtomically(dir, name, pr)
}

type progressReader struct {
	r      io.Reader
	onRead func(int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.onRead(int64(n))
	}
	return n, err
}

func nameFromResponse(resp *http.Response) string {
	if _, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); err == nil {
		if n, err := cleanName(params["filename"]); err == nil {
			return n
		}
	}
	if n, err := url.PathUnescape(path.Base(resp.Request.URL.Path)); err == nil {
		if n, err := cleanName(n); err == nil && n != "download" && n != "uc" {
			return n
		}
	}
	ext := ""
	if exts, _ := mime.ExtensionsByType(strings.Split(resp.Header.Get("Content-Type"), ";")[0]); len(exts) > 0 {
		ext = exts[0]
	}
	return "download-" + time.Now().Format("20060102-150405") + ext
}

// ensureDir creates folder rel (and its parents) under the root.
func (s *server) ensureDir(rel string) (string, error) {
	rel, err := cleanRel(rel)
	if err != nil {
		return "", errors.New("invalid folder name")
	}
	p := filepath.Join(s.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(p, 0o755); err != nil {
		return "", err
	}
	if t, err := s.resolve(rel); err != nil || !t.isDir {
		return "", errors.New("folder is not inside the file root")
	}
	return p, nil
}

// ---------- handlers ----------

func (s *server) handleFetchPage(w http.ResponseWriter, r *http.Request) {
	var folders []string
	if des, err := os.ReadDir(s.root); err == nil {
		for _, de := range des {
			if de.IsDir() && !strings.HasPrefix(de.Name(), ".") {
				folders = append(folders, de.Name())
			}
		}
	}
	s.render(w, "fetch", map[string]any{"Folders": folders, "Folder": r.URL.Query().Get("folder")})
}

func (s *server) handleFetchJobs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.fetcher.snapshot())
}

func (s *server) handleFetchClear(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]int{"cleared": s.fetcher.clearFinished()})
}

var linkRe = regexp.MustCompile(`https?://\S+`)

func (s *server) handleFetchAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Links, Folder string
		Convert       bool
	}
	if json.NewDecoder(io.LimitReader(r.Body, 256*1024)).Decode(&req) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	folder, err := cleanRel(req.Folder)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid folder name"})
		return
	}
	links := linkRe.FindAllString(req.Links, 50)
	if len(links) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no http(s) links found"})
		return
	}
	var ids []string
	for _, l := range links {
		ids = append(ids, s.fetcher.add(strings.TrimRight(l, ".,;)\"'"), folder, req.Convert).ID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"added": ids})
}
