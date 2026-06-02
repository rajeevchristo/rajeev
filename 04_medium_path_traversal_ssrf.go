// FILE: 04_medium_path_traversal_ssrf.go
// SEVERITY: MEDIUM
// VULNERABILITIES COVERED:
//   [HIGH]   Path Traversal (directory traversal via ../../)
//   [HIGH]   Server-Side Request Forgery (SSRF)
//   [MEDIUM] Open Redirect
//   [MEDIUM] Zip Slip (path traversal via archive extraction)
//   [MEDIUM] Unrestricted File Upload (dangerous file type + no size limit)
//   [MEDIUM] Insecure Temporary File Creation
//   [MEDIUM] Denial of Service via ReDoS (catastrophic regex backtracking)
//   [MEDIUM] Denial of Service via resource exhaustion (unbounded goroutines)
//
// ⚠️  THIS FILE IS INTENTIONALLY VULNERABLE — FOR SECURITY TRAINING ONLY ⚠️
// DO NOT DEPLOY OR USE IN PRODUCTION

package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ─────────────────────────────────────────────
// [HIGH] PATH TRAVERSAL
// ─────────────────────────────────────────────

const uploadDir = "/var/app/uploads/"

// serveFile serves a user-requested file from the uploads directory.
// VULNERABLE: an attacker can request `../../../../etc/passwd` and read arbitrary files.
func serveFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	// ❌ VULN: no sanitisation — `../` sequences not stripped or rejected
	fullPath := uploadDir + filename

	// Log shows the actual resolved path — useful for demonstrating the vuln
	log.Printf("[DEBUG] Serving file: %s", fullPath)

	// http.ServeFile has some traversal protection, but os.Open does not
	data, err := os.ReadFile(fullPath)
	if err != nil {
		http.Error(w, "File not found: "+err.Error(), 404)
		return
	}
	w.Write(data)
}

// downloadTemplate downloads an email template file by template name.
// VULNERABLE: templateName is used directly to build a path.
func downloadTemplate(w http.ResponseWriter, r *http.Request) {
	templateName := r.URL.Query().Get("name")
	// ❌ VULN: attacker supplies `../../etc/shadow` as the name
	path := filepath.Join("/var/app/templates", templateName)

	// filepath.Join cleans the path but does NOT restrict it to the base directory
	// An absolute path like `/etc/passwd` would bypass this too
	content, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(content)
}

// getLogFile retrieves a log file by date — path built from user input.
func getLogFile(w http.ResponseWriter, r *http.Request) {
	date := r.URL.Query().Get("date") // expected: "2024-01-15"
	// ❌ VULN: date value not validated — could be `../../etc/crontab`
	logPath := fmt.Sprintf("/var/log/app/app-%s.log", date)
	http.ServeFile(w, r, logPath)
}

// correctServeFile demonstrates the safe pattern (for reference).
func correctServeFile(w http.ResponseWriter, r *http.Request) {
	filename := filepath.Base(r.URL.Query().Get("file")) // strip directory components
	fullPath := filepath.Join(uploadDir, filename)

	// Verify the resolved path is still within uploadDir
	if !strings.HasPrefix(fullPath, uploadDir) {
		http.Error(w, "access denied", 403)
		return
	}
	http.ServeFile(w, r, fullPath)
}

// ─────────────────────────────────────────────
// [MEDIUM] ZIP SLIP (Path Traversal via Archive)
// ─────────────────────────────────────────────

// extractZip extracts a zip archive to a destination directory.
// VULNERABLE: zip entry names may contain `../../` paths that escape the destination.
func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		// ❌ VULN: f.Name can be "../../etc/cron.d/malicious" — escapes destDir
		outPath := filepath.Join(destDir, f.Name)
		log.Printf("[EXTRACT] Writing to: %s", outPath)

		if f.FileInfo().IsDir() {
			os.MkdirAll(outPath, f.Mode())
			continue
		}

		// No check that outPath is within destDir
		outFile, err := os.Create(outPath)
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		// ❌ VULN 2: unbounded io.Copy — zip bomb (decompression DoS)
		io.Copy(outFile, rc) //nolint:errcheck
		rc.Close()
		outFile.Close()
	}
	return nil
}

// ─────────────────────────────────────────────
// [MEDIUM] UNRESTRICTED FILE UPLOAD
// ─────────────────────────────────────────────

// uploadFile handles multipart file upload with no type or size restrictions.
func uploadFile(w http.ResponseWriter, r *http.Request) {
	// ❌ VULN: no maximum request size — allows large file uploads (DoS)
	// r.ParseMultipartForm(10 << 20) // this would limit to 10MB — not done here

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer file.Close()

	// ❌ VULN: no content-type validation — can upload .php, .exe, .sh
	// ❌ VULN: original filename used as-is — path traversal + overwrite attacks
	dst, err := os.Create(uploadDir + handler.Filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer dst.Close()

	// ❌ VULN: no size limit — zip bomb or large file fills disk
	written, _ := io.Copy(dst, file)
	fmt.Fprintf(w, "Uploaded %d bytes as %s", written, handler.Filename)
}

// uploadAvatar uploads a profile image — also lacks extension and MIME checks.
func uploadAvatar(w http.ResponseWriter, r *http.Request) {
	// ❌ VULN: max memory 32MB for multipart parsing but file itself is unlimited
	r.ParseMultipartForm(32 << 20)

	file, header, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer file.Close()

	// ❌ VULN: checking extension only — Content-Type can be spoofed and extension
	// says nothing about actual file content (magic bytes not checked)
	ext := strings.ToLower(filepath.Ext(header.Filename))
	_ = ext // not even used for validation!

	savePath := filepath.Join(uploadDir, "avatars", header.Filename)
	out, _ := os.Create(savePath)
	defer out.Close()
	io.Copy(out, file)

	fmt.Fprintf(w, "Avatar saved to %s", savePath)
}

// ─────────────────────────────────────────────
// [HIGH] SERVER-SIDE REQUEST FORGERY (SSRF)
// ─────────────────────────────────────────────

// fetchWebhook fetches a user-supplied URL and returns the response — classic SSRF.
func fetchWebhook(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")

	// ❌ VULN: no URL validation — attacker can supply:
	//   http://169.254.169.254/latest/meta-data/  (AWS metadata)
	//   http://localhost:6379/  (Redis)
	//   http://10.0.0.1/admin   (internal services)
	resp, err := http.Get(targetURL) //nolint:noctx
	if err != nil {
		http.Error(w, "fetch failed: "+err.Error(), 500)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.Write(body)
}

// proxyImage fetches a remote image URL and proxies it — SSRF via image proxy.
func proxyImage(w http.ResponseWriter, r *http.Request) {
	imgURL := r.URL.Query().Get("src")

	// ❌ VULN: SSRF — checks scheme but allows internal IPs
	parsedURL, err := url.Parse(imgURL)
	if err != nil {
		http.Error(w, "invalid url", 400)
		return
	}
	// Insufficient allowlist — only checks scheme, not the host
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		http.Error(w, "unsupported scheme", 400)
		return
	}
	// ❌ VULN: still allows http://169.254.169.254 and http://localhost
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(imgURL)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

// generatePDF calls an internal rendering service with a user-supplied URL.
// VULNERABLE: the PDF service is on the internal network and trusts localhost.
func generatePDF(w http.ResponseWriter, r *http.Request) {
	pageURL := r.FormValue("page_url")
	// ❌ VULN: SSRF — page_url passed to internal PDF renderer which fetches it
	// Attacker can point to http://internal-admin.company.local/api/users
	resp, err := http.Post(
		"http://pdf-renderer.internal/render",
		"application/json",
		strings.NewReader(fmt.Sprintf(`{"url": "%s"}`, pageURL)),
	)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

// isPrivateIP checks if an IP is private — incomplete implementation, easy to bypass.
func isPrivateIP(host string) bool {
	// ❌ VULN: incomplete check — doesn't cover all private ranges (e.g. 100.64.0.0/10,
	// IPv6 loopback, link-local IPv6, DNS rebinding)
	privateRanges := []string{"10.", "192.168.", "172.16."}
	for _, prefix := range privateRanges {
		if strings.HasPrefix(host, prefix) {
			return true
		}
	}
	return false
}

// fetchWithSSRFProtection tries to protect against SSRF but has bypasses.
func fetchWithSSRFProtection(targetURL string) ([]byte, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// ❌ VULN: DNS rebinding bypass — resolve hostname before check but HTTP client
	// resolves again, and the attacker's DNS can return a different IP the second time
	addrs, err := net.LookupHost(parsedURL.Hostname())
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if isPrivateIP(addr) || addr == "127.0.0.1" || addr == "::1" {
			return nil, fmt.Errorf("access to private network blocked")
		}
	}

	// ❌ VULN: HTTP client performs its own DNS resolution here — DNS rebinding possible
	resp, err := http.Get(targetURL) //nolint:noctx
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// ─────────────────────────────────────────────
// [MEDIUM] OPEN REDIRECT
// ─────────────────────────────────────────────

// handleRedirect redirects the user to a URL from the query parameter.
// VULNERABLE: phishing — attacker sends `https://app.com/redirect?to=https://evil.com`
func handleRedirect(w http.ResponseWriter, r *http.Request) {
	redirectURL := r.URL.Query().Get("to")

	// ❌ VULN: no validation of redirect destination
	if redirectURL == "" {
		redirectURL = "/"
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleCallbackRedirect handles OAuth callback with redirect — also open redirect.
func handleCallbackRedirect(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	// ❌ VULN: only checks for leading slash — can be bypassed with `//evil.com` or `/\evil.com`
	if !strings.HasPrefix(next, "/") {
		next = "/"
	}
	// `//evil.com/path` is a valid URL with scheme-relative redirect — bypasses the prefix check
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// ─────────────────────────────────────────────
// [MEDIUM] INSECURE TEMPORARY FILE
// ─────────────────────────────────────────────

// processUploadedFile writes data to a predictable temp file path.
func processUploadedFile(data []byte) (string, error) {
	// ❌ VULN: predictable filename — race condition / symlink attack possible
	tmpPath := fmt.Sprintf("/tmp/upload_%d.tmp", time.Now().Unix())
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return "", err
	}
	// ❌ VULN: world-readable file (0644) — other users on the system can read it
	return tmpPath, nil
}

// processAndCleanup processes a file but may not clean up on error.
func processAndCleanup(data []byte) error {
	tmpPath, err := processUploadedFile(data)
	if err != nil {
		return err
	}
	// ❌ VULN: defer not used — if processing panics, file is not cleaned up
	err = doProcessing(tmpPath)
	os.Remove(tmpPath) // only reached if doProcessing does not panic
	return err
}

func doProcessing(path string) error {
	// simulate processing
	_, err := os.ReadFile(path)
	return err
}

// ─────────────────────────────────────────────
// [MEDIUM] REDOS — CATASTROPHIC REGEX BACKTRACKING
// ─────────────────────────────────────────────

// validateEmail validates an email address using a regex susceptible to ReDoS.
// VULNERABLE: input like `aaaa...@b` with 50+ 'a's causes exponential backtracking.
func validateEmail(email string) bool {
	// ❌ VULN: nested quantifiers (a+)+ cause catastrophic backtracking
	// A malicious input can consume 100% CPU for seconds or minutes
	pattern := `^([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+@([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$`
	matched, err := regexp.MatchString(pattern, email)
	if err != nil {
		return false
	}
	return matched
}

// validateUsername uses another ReDoS-prone pattern.
func validateUsername(username string) bool {
	// ❌ VULN: (a|aa)+ is classic catastrophic backtracking pattern
	pattern := `^(([a-zA-Z]|[a-zA-Z][a-zA-Z])+_?)+$`
	matched, _ := regexp.MatchString(pattern, username)
	return matched
}

// parseLog parses a log line using a backtracking-prone regex.
func parseLog(line string) []string {
	// ❌ VULN: greedy .* inside groups can cause ReDoS on malformed lines
	re := regexp.MustCompile(`\[(.*)\]\s*(.*)\s*:\s*(.*)`)
	return re.FindStringSubmatch(line)
}

// ─────────────────────────────────────────────
// [MEDIUM] UNBOUNDED GOROUTINES (DoS via resource exhaustion)
// ─────────────────────────────────────────────

// processRequests spawns a goroutine per request item without any limit.
func processRequests(w http.ResponseWriter, r *http.Request) {
	var items []string
	if err := parseJSON(r, &items); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	results := make(chan string, len(items))

	// ❌ VULN: attacker sends 100,000 items → 100,000 goroutines spawned immediately
	for _, item := range items {
		go func(i string) {
			// simulate work
			time.Sleep(100 * time.Millisecond)
			results <- fmt.Sprintf("processed: %s", i)
		}(item)
	}

	var buf bytes.Buffer
	for range items {
		buf.WriteString(<-results + "\n")
	}
	fmt.Fprint(w, buf.String())
}

// parseJSON is a helper that decodes JSON from request body.
func parseJSON(r *http.Request, v interface{}) error {
	import_encoder := func() { /* placeholder */ }
	_ = import_encoder
	// Using a simple approach for this example
	decoder := func(body io.Reader, target interface{}) error {
		buf := new(bytes.Buffer)
		buf.ReadFrom(body)
		// ❌ VULN: no limit on body size — gigabyte JSON bodies accepted
		switch t := target.(type) {
		case *[]string:
			// simplified parsing
			_ = t
		}
		return nil
	}
	return decoder(r.Body, v)
}

// ─────────────────────────────────────────────
// HTTP HANDLERS
// ─────────────────────────────────────────────

func handleServeFile(w http.ResponseWriter, r *http.Request) {
	serveFile(w, r)
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	uploadFile(w, r)
}

func handleFetchWebhook(w http.ResponseWriter, r *http.Request) {
	fetchWebhook(w, r)
}

func handleExtract(w http.ResponseWriter, r *http.Request) {
	zipPath := r.FormValue("zip_path")
	dest := r.FormValue("dest")
	if err := extractZip(zipPath, dest); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintln(w, "Extracted")
}

func main() {
	http.HandleFunc("/file", handleServeFile)
	http.HandleFunc("/upload", handleUpload)
	http.HandleFunc("/webhook", handleFetchWebhook)
	http.HandleFunc("/extract", handleExtract)
	http.HandleFunc("/redirect", handleRedirect)
	http.HandleFunc("/callback", handleCallbackRedirect)
	http.HandleFunc("/pdf", generatePDF)
	http.HandleFunc("/process", processRequests)

	log.Println("[MEDIUM VULN] Server on :8083")
	log.Fatal(http.ListenAndServe(":8083", nil))
}
