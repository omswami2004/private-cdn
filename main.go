// private-cdn: a single-binary private file server.
//
// Everything sits behind one username and password, except /share/<code>
// links. Every file, including every file inside a .zip, gets a stable,
// unguessable share link that streams without a login (with Range support, so
// videos seek). /fetch downloads Google Drive, Dropbox and direct links onto
// the server.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed web/*.html
var webFS embed.FS

type config struct {
	Addr         string // listen address, e.g. 127.0.0.1:8090
	Root         string // directory that is served
	StateDir     string // secret key and share-link index
	PublicURL    string // e.g. https://cdn.axiosiiitl.dev (used for links and origin checks)
	User         string
	PasswordHash string
}

type server struct {
	cfg        config
	root       string // Root with symlinks resolved
	sessionKey []byte
	shares     *shareStore
	zips       *zipCache
	fetcher    *fetcher
	limiter    *loginLimiter
	tmpl       *template.Template
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		if err := hashPasswordCmd(); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}

	cfg := config{
		Addr:         env("CDN_ADDR", "127.0.0.1:8090"),
		Root:         env("CDN_ROOT", "/srv/files"),
		StateDir:     env("CDN_STATE_DIR", "/var/lib/private-cdn"),
		PublicURL:    strings.TrimRight(env("CDN_PUBLIC_URL", "https://cdn.axiosiiitl.dev"), "/"),
		User:         os.Getenv("CDN_USER"),
		PasswordHash: os.Getenv("CDN_PASSWORD_HASH"),
	}
	s, err := newServer(cfg)
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("serving %s on %s as %s", s.root, cfg.Addr, cfg.PublicURL)
	log.Fatal(srv.ListenAndServe())
}

func newServer(cfg config) (*server, error) {
	if cfg.User == "" || cfg.PasswordHash == "" {
		return nil, errors.New("CDN_USER and CDN_PASSWORD_HASH must be set (see `private-cdn hash-password`)")
	}
	if _, err := parsePasswordHash(cfg.PasswordHash); err != nil {
		return nil, fmt.Errorf("CDN_PASSWORD_HASH: %w", err)
	}
	root, err := filepath.EvalSymlinks(cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("CDN_ROOT: %w", err)
	}
	root, _ = filepath.Abs(root)
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	secret, err := loadSecret(filepath.Join(cfg.StateDir, "secret"))
	if err != nil {
		return nil, err
	}
	shares, err := openShareStore(filepath.Join(cfg.StateDir, "shares.jsonl"), deriveKey(secret, "share"))
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("").Funcs(template.FuncMap{"size": humanSize}).ParseFS(webFS, "web/*.html")
	if err != nil {
		return nil, err
	}
	s := &server{
		cfg:        cfg,
		root:       root,
		sessionKey: deriveKey(secret, "session"),
		shares:     shares,
		zips:       newZipCache(32),
		limiter:    newLoginLimiter(),
		tmpl:       tmpl,
	}
	s.fetcher = newFetcher(s, 3)
	return s, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	// Public: login and share links.
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /share/{code}", s.handleShare)
	mux.HandleFunc("GET /share/{code}/{name...}", s.handleShare)

	// Everything else needs the login.
	mux.Handle("GET /{$}", s.auth(http.RedirectHandler("/files/", http.StatusFound)))
	mux.Handle("GET /files/{path...}", s.auth(http.HandlerFunc(s.handleBrowse)))
	mux.Handle("GET /api/link", s.auth(http.HandlerFunc(s.handleLink)))
	mux.Handle("POST /api/upload", s.auth(http.HandlerFunc(s.handleUpload)))
	mux.Handle("POST /api/mkdir", s.auth(http.HandlerFunc(s.handleMkdir)))
	mux.Handle("POST /api/delete", s.auth(http.HandlerFunc(s.handleDelete)))
	mux.Handle("GET /fetch", s.auth(http.HandlerFunc(s.handleFetchPage)))
	mux.Handle("GET /fetch/api/jobs", s.auth(http.HandlerFunc(s.handleFetchJobs)))
	mux.Handle("POST /fetch/api/jobs", s.auth(http.HandlerFunc(s.handleFetchAdd)))
	mux.Handle("POST /fetch/api/clear", s.auth(http.HandlerFunc(s.handleFetchClear)))

	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Robots-Tag", "noindex, nofollow")
		next.ServeHTTP(w, r)
	})
}

// loadSecret reads the 32-byte server secret, creating it on first start.
func loadSecret(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil && len(b) >= 32 {
		return b, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

func deriveKey(secret []byte, purpose string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(purpose))
	return m.Sum(nil)
}

func humanSize(n int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}
