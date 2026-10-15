package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testURL = "https://cdn.example.test"

func newTestServer(t *testing.T) (*server, http.Handler, string) {
	t.Helper()
	root := t.TempDir()
	hash, err := hashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	s, err := newServer(config{Root: root, StateDir: t.TempDir(), PublicURL: testURL, User: "me", PasswordHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	return s, s.routes(), root
}

func do(h http.Handler, method, target string, body io.Reader, hdr map[string]string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func login(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	form := url.Values{"username": {"me"}, "password": {"correct horse"}}
	rec := do(h, "POST", "/login", strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: got %d", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func writeZip(t *testing.T, path string, files map[string][]byte, method uint16) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, data := range files {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: method})
		if err != nil {
			t.Fatal(err)
		}
		w.Write(data)
	}
	zw.Close()
	f.Close()
}

func TestPasswordHash(t *testing.T) {
	h, _ := hashPassword("secret-pass")
	if !checkPassword(h, "secret-pass") || checkPassword(h, "wrong") {
		t.Fatal("password check broken")
	}
	if strings.Contains(h, "$") {
		t.Fatal("hash must be safe for systemd EnvironmentFile")
	}
}

func TestLoginRequired(t *testing.T) {
	_, h, root := newTestServer(t)
	os.WriteFile(filepath.Join(root, "a.txt"), []byte("hi"), 0o644)
	if rec := do(h, "GET", "/files/", nil, nil, nil); rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/login") {
		t.Fatalf("browse without login: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if rec := do(h, "GET", "/files/a.txt", nil, nil, nil); rec.Code != http.StatusFound {
		t.Fatalf("file without login: %d", rec.Code)
	}
	if rec := do(h, "GET", "/fetch", nil, nil, nil); rec.Code != http.StatusFound {
		t.Fatalf("fetch without login: %d", rec.Code)
	}
	if rec := do(h, "GET", "/fetch/api/jobs", nil, nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("fetch api without login: %d", rec.Code)
	}
	forged := &http.Cookie{Name: sessionCookie, Value: "bWV8OTk5OTk5OTk5OQ.AAAA"}
	if rec := do(h, "GET", "/files/", nil, nil, forged); rec.Code != http.StatusFound {
		t.Fatalf("forged cookie accepted: %d", rec.Code)
	}
	bad := url.Values{"username": {"me"}, "password": {"nope"}}
	if rec := do(h, "POST", "/login", strings.NewReader(bad.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", rec.Code)
	}
	c := login(t, h)
	if rec := do(h, "GET", "/files/", nil, nil, c); rec.Code != 200 || !strings.Contains(rec.Body.String(), "a.txt") {
		t.Fatalf("browse with login: %d", rec.Code)
	}
}

func TestOpenRedirect(t *testing.T) {
	for _, n := range []string{"//evil.com", "https://evil.com", "/\\evil.com", ""} {
		if safeNext(n) != "/files/" {
			t.Fatalf("safeNext(%q) = %q", n, safeNext(n))
		}
	}
}

func TestShareLinksAndZipStreaming(t *testing.T) {
	s, h, root := newTestServer(t)
	video := make([]byte, 300_000)
	rand.Read(video)
	writeZip(t, filepath.Join(root, "show.zip"), map[string][]byte{"s1/ep1.mp4": video}, zip.Store)
	writeZip(t, filepath.Join(root, "packed.zip"), map[string][]byte{"docs/readme.txt": bytes.Repeat([]byte("abcdef"), 50_000)}, zip.Deflate)
	c := login(t, h)

	// Zip lists as a folder.
	rec := do(h, "GET", "/files/show.zip/s1/", nil, nil, c)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "ep1.mp4") {
		t.Fatalf("zip listing: %d", rec.Code)
	}

	// Clicking a zip opens it; Download forces an attachment.
	rec = do(h, "GET", "/files/", nil, nil, c)
	if !strings.Contains(rec.Body.String(), `href="/files/show.zip/"`) || !strings.Contains(rec.Body.String(), `href="/files/show.zip?download=1"`) {
		t.Fatal("zip should link to its folder view, with a separate Download link")
	}
	rec = do(h, "GET", "/files/show.zip?download=1", nil, nil, c)
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("download: %d %q", rec.Code, rec.Header().Get("Content-Disposition"))
	}

	// Share link: no cookie needed, Range works on a stored entry.
	link := s.shares.url(testURL, "show.zip/s1/ep1.mp4")
	path := strings.TrimPrefix(link, testURL)
	if len(strings.TrimPrefix(path, "/share/")) != shareCodeLen || strings.Contains(path, "ep1") {
		t.Fatalf("share link leaks path or wrong length: %s", path)
	}
	rec = do(h, "GET", path, nil, map[string]string{"Range": "bytes=1000-1999"}, nil)
	if rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), video[1000:2000]) {
		t.Fatalf("range on stored entry: %d len=%d", rec.Code, rec.Body.Len())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "video/mp4" {
		t.Fatalf("content type %q", ct)
	}

	// Range on a deflated entry.
	want := bytes.Repeat([]byte("abcdef"), 50_000)
	p2 := strings.TrimPrefix(s.shares.url(testURL, "packed.zip/docs/readme.txt"), testURL)
	rec = do(h, "GET", p2, nil, map[string]string{"Range": "bytes=200000-200099"}, nil)
	if rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), want[200000:200100]) {
		t.Fatalf("range on deflated entry: %d", rec.Code)
	}

	// Unknown or tampered codes are 404.
	for _, bad := range []string{"/share/AAAAAAAAAAAAAAAA", path[:len(path)-1] + "x"} {
		if rec := do(h, "GET", bad, nil, nil, nil); rec.Code != http.StatusNotFound {
			t.Fatalf("bad code %s: %d", bad, rec.Code)
		}
	}

	// Links survive a restart (index on disk) and stay stable.
	s2, err := newServer(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s2.shares.url(testURL, "show.zip/s1/ep1.mp4") != link {
		t.Fatal("share link changed across restart")
	}
	if rec := do(s2.routes(), "GET", path, nil, nil, nil); rec.Code != 200 {
		t.Fatalf("share after restart: %d", rec.Code)
	}

	// Served files are sandboxed so an uploaded .html can't act as the site.
	os.WriteFile(filepath.Join(root, "x.html"), []byte("<script>1</script>"), 0o644)
	p3 := strings.TrimPrefix(s.shares.url(testURL, "x.html"), testURL)
	if rec := do(h, "GET", p3, nil, nil, nil); rec.Header().Get("Content-Security-Policy") != "sandbox" {
		t.Fatal("missing sandbox CSP on served file")
	}
}

func TestTraversalAndHidden(t *testing.T) {
	s, h, root := newTestServer(t)
	os.WriteFile(filepath.Join(root, ".secret.part"), []byte("x"), 0o644)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "passwd"), []byte("x"), 0o644)
	os.Symlink(outside, filepath.Join(root, "escape"))
	c := login(t, h)
	for _, p := range []string{"/files/../etc/passwd", "/files/%2e%2e/etc/passwd", "/files/.secret.part", "/files/escape/passwd", "/files/escape/"} {
		if rec := do(h, "GET", p, nil, nil, c); rec.Code == 200 {
			t.Fatalf("%s should not be served", p)
		}
	}
	if _, err := s.resolve("escape/passwd"); err == nil {
		t.Fatal("symlink escape resolved")
	}
	if rec := do(h, "GET", "/api/link?path=../x", nil, nil, c); rec.Code != http.StatusNotFound {
		t.Fatalf("link outside root: %d", rec.Code)
	}
}

func TestUploadDeleteAndCSRF(t *testing.T) {
	_, h, root := newTestServer(t)
	c := login(t, h)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "../../clip.mp4")
	fw.Write([]byte("video"))
	mw.Close()
	hdr := map[string]string{"Content-Type": mw.FormDataContentType()}

	// Cross-site upload is refused.
	hdr["Origin"] = "https://evil.example"
	if rec := do(h, "POST", "/api/upload?dir=", bytes.NewReader(body.Bytes()), hdr, c); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site upload: %d", rec.Code)
	}
	hdr["Origin"] = testURL
	rec := do(h, "POST", "/api/upload?dir=", bytes.NewReader(body.Bytes()), hdr, c)
	if rec.Code != 200 {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}
	if b, err := os.ReadFile(filepath.Join(root, "clip.mp4")); err != nil || string(b) != "video" {
		t.Fatal("upload did not land in root as clip.mp4")
	}
	// Second upload with the same name doesn't overwrite.
	do(h, "POST", "/api/upload?dir=", bytes.NewReader(body.Bytes()), hdr, c)
	if _, err := os.Stat(filepath.Join(root, "clip (2).mp4")); err != nil {
		t.Fatal("expected clip (2).mp4")
	}

	js := map[string]string{"Origin": testURL, "Content-Type": "application/json"}
	b, _ := json.Marshal(map[string]string{"Path": "clip.mp4"})
	if rec := do(h, "POST", "/api/delete", bytes.NewReader(b), js, c); rec.Code != 200 {
		t.Fatalf("delete: %d", rec.Code)
	}
	b, _ = json.Marshal(map[string]string{"Path": ""})
	if rec := do(h, "POST", "/api/delete", bytes.NewReader(b), js, c); rec.Code == 200 {
		t.Fatal("deleting the root must be refused")
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatal("root gone")
	}
}

func TestDriveAndDropboxLinks(t *testing.T) {
	u, _ := url.Parse("https://drive.google.com/file/d/1AbCdEfGhIjKlMnOp/view?usp=sharing")
	if got, drive := directURL(u); !drive || !strings.Contains(got, "id=1AbCdEfGhIjKlMnOp") {
		t.Fatalf("drive: %s", got)
	}
	u, _ = url.Parse("https://www.dropbox.com/scl/fi/abc/file.zip?rlkey=x&dl=0")
	if got, _ := directURL(u); !strings.Contains(got, "dl=1") || strings.Contains(got, "dl=0") {
		t.Fatalf("dropbox: %s", got)
	}
	page := `<form id="download-form" action="https://drive.usercontent.google.com/download" method="get">
<input type="hidden" name="id" value="ID1"><input type="hidden" name="confirm" value="t"><input type="hidden" name="uuid" value="U-1"></form>`
	got, ok := driveConfirm(page)
	if !ok || !strings.Contains(got, "uuid=U-1") || !strings.Contains(got, "id=ID1") {
		t.Fatalf("drive confirm: %s", got)
	}
}

func TestFetchRefusesPrivateAddresses(t *testing.T) {
	for _, a := range []string{"127.0.0.1:80", "10.0.0.1:443", "192.168.1.1:80", "169.254.169.254:80", "[::1]:80", "100.64.1.1:80"} {
		if refusePrivate("tcp", a, nil) == nil {
			t.Fatalf("%s allowed", a)
		}
	}
	if refusePrivate("tcp", "1.1.1.1:443", nil) != nil {
		t.Fatal("public address refused")
	}
}

func TestFetchClearKeepsActiveJobs(t *testing.T) {
	s, h, _ := newTestServer(t)
	c := login(t, h)
	f := s.fetcher
	f.jobs = []*job{{ID: "a", Status: "done"}, {ID: "b", Status: "downloading"}, {ID: "c", Status: "error"}, {ID: "d", Status: "queued"}}

	if rec := do(h, "POST", "/fetch/api/clear", nil, map[string]string{"Origin": "https://evil.example"}, c); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site clear: %d", rec.Code)
	}
	rec := do(h, "POST", "/fetch/api/clear", nil, map[string]string{"Origin": testURL}, c)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"cleared":2`) {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body)
	}
	var ids []string
	for _, j := range f.snapshot() {
		ids = append(ids, j.ID)
	}
	if strings.Join(ids, ",") != "d,b" {
		t.Fatalf("kept %v, want the queued and downloading jobs", ids)
	}
}
