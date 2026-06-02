// FILE: 05_low_info_disclosure.go
// SEVERITY: LOW
// VULNERABILITIES COVERED:
//   [LOW]    Information disclosure via verbose error messages
//   [LOW]    Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
//   [LOW]    Version/stack disclosure in HTTP response headers
//   [LOW]    Debug endpoints left enabled in production
//   [LOW]    Insecure CORS configuration (wildcard origin)
//   [LOW]    Clickjacking (missing X-Frame-Options)
//   [LOW]    HTTP instead of HTTPS (no HSTS)
//   [LOW]    Verbose stack traces returned to clients
//   [LOW]    Excessive data exposure in API responses
//   [LOW]    Unvalidated Content-Type (MIME sniffing)
//   [LOW]    Business logic: no rate limiting on public endpoints
//   [LOW]    Cache control misconfiguration (sensitive pages cached)
//
// ⚠️  THIS FILE IS INTENTIONALLY VULNERABLE — FOR SECURITY TRAINING ONLY ⚠️
// DO NOT DEPLOY OR USE IN PRODUCTION

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
	"time"
)

// ─────────────────────────────────────────────
// APP VERSION INFO (leaks to clients)
// ─────────────────────────────────────────────

const (
	// ❌ VULN: exposing exact versions helps attackers find known CVEs
	AppVersion    = "1.2.3"
	GoVersion     = "go1.21.0"
	FrameworkName = "custom-framework/2.0.1"
	DBVersion     = "PostgreSQL 14.2"
	OSInfo        = "Ubuntu 22.04 LTS"
)

// ─────────────────────────────────────────────
// [LOW] VERSION DISCLOSURE VIA RESPONSE HEADERS
// ─────────────────────────────────────────────

// versionMiddleware adds server version info to every response header.
func versionMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ❌ VULN: exposing server software and exact versions in headers
		w.Header().Set("Server", "MyApp/"+AppVersion)
		w.Header().Set("X-Powered-By", FrameworkName)
		w.Header().Set("X-Runtime", GoVersion)
		w.Header().Set("X-DB-Version", DBVersion)
		w.Header().Set("X-OS", OSInfo)
		next(w, r)
	}
}

// ─────────────────────────────────────────────
// [LOW] MISSING SECURITY HEADERS
// ─────────────────────────────────────────────

// insecureHandler serves a page with no security headers at all.
func insecureHandler(w http.ResponseWriter, r *http.Request) {
	// ❌ VULN: Missing headers:
	//   Content-Security-Policy       — XSS mitigation
	//   X-Frame-Options               — clickjacking
	//   X-Content-Type-Options        — MIME sniffing
	//   Strict-Transport-Security     — HSTS / downgrade attacks
	//   Referrer-Policy               — referer leakage
	//   Permissions-Policy            — feature access control
	//   Cache-Control                 — sensitive data in browser cache
	fmt.Fprintln(w, "<html><body>Welcome to the app!</body></html>")
}

// secureHeadersMiddleware shows what the headers SHOULD look like (for reference).
func secureHeadersMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ✅ CORRECT: comprehensive security headers
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		next(w, r)
	}
}

// ─────────────────────────────────────────────
// [LOW] INSECURE CORS CONFIGURATION
// ─────────────────────────────────────────────

// corsMiddleware applies a wildcard CORS policy — allows any origin to make requests.
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ❌ VULN: wildcard origin + allow credentials = any site can make authenticated requests
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-CSRF-Token")
		// Note: Access-Control-Allow-Credentials: true + wildcard origin is blocked by browsers
		// but some devs set the request's actual origin instead:
		origin := r.Header.Get("Origin")
		if origin != "" {
			// ❌ VULN: reflecting ANY origin back — allows cross-site reading of responses
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

// ─────────────────────────────────────────────
// [LOW] VERBOSE ERROR MESSAGES & STACK TRACES
// ─────────────────────────────────────────────

// DatabaseError wraps a database error with internal details.
type DatabaseError struct {
	Query    string
	Table    string
	Host     string
	Port     int
	DBName   string
	User     string
	Original error
}

func (e *DatabaseError) Error() string {
	// ❌ VULN: returns internal DB topology, credentials context, and query to the client
	return fmt.Sprintf("DB error on host=%s port=%d db=%s user=%s table=%s query=%s: %v",
		e.Host, e.Port, e.DBName, e.User, e.Table, e.Query, e.Original)
}

// handleDBRequest runs a query and returns the full error to the client.
func handleDBRequest(w http.ResponseWriter, r *http.Request) {
	err := simulateDBError()
	if err != nil {
		// ❌ VULN: full internal error (with host, port, credentials context) sent to user
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, "ok")
}

func simulateDBError() error {
	return &DatabaseError{
		Query:    "SELECT * FROM users WHERE id = 1",
		Table:    "users",
		Host:     "10.0.1.55",
		Port:     5432,
		DBName:   "production_db",
		User:     "app_user",
		Original: fmt.Errorf("connection refused"),
	}
}

// handlePanic recovers from panics and dumps the full stack trace to the HTTP response.
func handlePanic(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			// ❌ VULN: full stack trace with file paths and line numbers sent to client
			stack := debug.Stack()
			http.Error(w,
				fmt.Sprintf("Internal error: %v\n\nStack trace:\n%s", rec, string(stack)),
				http.StatusInternalServerError,
			)
		}
	}()
	// Simulate a panic
	var m map[string]string
	_ = m["key"] // nil map access — panics
}

// handleValidation returns the full input validation error including field values.
func handleValidation(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	if !isValidEmail(email) {
		// ❌ VULN: echoing back user input + internal validation logic in error
		http.Error(w,
			fmt.Sprintf("Validation failed for email '%s': must match regex ^[\\w.]+@[\\w]+\\.[\\w]{2,}$", email),
			http.StatusBadRequest,
		)
		return
	}
	fmt.Fprintln(w, "valid")
}

func isValidEmail(email string) bool {
	return len(email) > 0 && len(email) < 255
}

// ─────────────────────────────────────────────
// [LOW] DEBUG / ADMIN ENDPOINTS IN PRODUCTION
// ─────────────────────────────────────────────

// registerDebugRoutes registers pprof and debug routes on the production mux.
func registerDebugRoutes(mux *http.ServeMux) {
	// ❌ VULN: pprof endpoints expose heap dumps, goroutine stacks, CPU profiles
	// An attacker can extract secrets from heap, enumerate goroutines, and DoS via profiling
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	// ❌ VULN: debug info endpoint returns internal configuration
	mux.HandleFunc("/debug/info", debugInfo)
	mux.HandleFunc("/debug/env", debugEnv)
	mux.HandleFunc("/debug/goroutines", debugGoroutines)
	mux.HandleFunc("/health/detailed", detailedHealth)
}

// debugInfo returns internal application configuration.
func debugInfo(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"version":     AppVersion,
		"go_version":  runtime.Version(),
		"go_os":       runtime.GOOS,
		"go_arch":     runtime.GOARCH,
		"num_cpu":     runtime.NumCPU(),
		"num_gc":      runtime.NumGoroutine(),
		"db_host":     "10.0.1.55:5432",
		"db_name":     "production_db",
		"db_user":     "app_user",
		"redis_host":  "10.0.1.56:6379",
		"environment": "production",
		"secret_key":  "supersecret123", // ❌ VULN: secret in debug output!
	}
	// ❌ VULN: no auth check — anyone can access /debug/info
	json.NewEncoder(w).Encode(info)
}

// debugEnv dumps ALL environment variables — may contain API keys, DB passwords, etc.
func debugEnv(w http.ResponseWriter, r *http.Request) {
	// ❌ VULN: exposes all env vars including AWS_SECRET_ACCESS_KEY, DATABASE_URL, etc.
	envVars := os.Environ()
	for _, e := range envVars {
		fmt.Fprintln(w, e)
	}
}

// debugGoroutines dumps all goroutine stacks.
func debugGoroutines(w http.ResponseWriter, r *http.Request) {
	// ❌ VULN: goroutine dump may reveal internal file paths, function names, data
	buf := make([]byte, 1<<20) // 1MB
	n := runtime.Stack(buf, true)
	w.Write(buf[:n])
}

// detailedHealth returns detailed health info including dependency statuses.
func detailedHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":   "ok",
		"db_host":  "10.0.1.55",
		"db_port":  5432,
		"db_alive": true,
		"redis":    "10.0.1.56:6379",
		"version":  AppVersion,
		"uptime":   time.Since(startTime).String(),
		// ❌ VULN: internal network topology exposed to unauthenticated callers
		"internal_services": map[string]string{
			"auth":    "http://auth.internal:8001",
			"payment": "http://payment.internal:8002",
			"admin":   "http://admin.internal:9000",
		},
	}
	json.NewEncoder(w).Encode(health)
}

var startTime = time.Now()

// ─────────────────────────────────────────────
// [LOW] EXCESSIVE DATA EXPOSURE IN API RESPONSES
// ─────────────────────────────────────────────

// FullUserModel is the complete database model.
type FullUserModel struct {
	ID                int       `json:"id"`
	Username          string    `json:"username"`
	Email             string    `json:"email"`
	PasswordHash      string    `json:"password_hash"`       // ❌ should never be in response
	PasswordResetToken string   `json:"password_reset_token"` // ❌ exposes active reset token
	TwoFactorSecret   string    `json:"two_factor_secret"`    // ❌ TOTP seed exposed
	Role              string    `json:"role"`
	IsAdmin           bool      `json:"is_admin"`
	SSN               string    `json:"ssn"`                 // ❌ PII
	DateOfBirth       time.Time `json:"date_of_birth"`       // ❌ PII
	CreditCardLast4   string    `json:"credit_card_last4"`
	FullCreditCard    string    `json:"full_credit_card"`     // ❌ PCI data!
	InternalNotes     string    `json:"internal_notes"`       // ❌ admin-only notes
	CreatedAt         time.Time `json:"created_at"`
	LastLoginAt       time.Time `json:"last_login_at"`
	FailedLoginCount  int       `json:"failed_login_count"`   // ❌ reveals lock status
	IsLocked          bool      `json:"is_locked"`
}

// getUserAPI returns the full internal model to the client — too much data.
func getUserAPI(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, _ := strconv.Atoi(idStr)

	// ❌ VULN: entire model including password hash, 2FA secret, credit card serialised to JSON
	user := &FullUserModel{
		ID:                 id,
		Username:           "johndoe",
		Email:              "john@example.com",
		PasswordHash:       "$2a$12$abcdefghijklmnopqrstuvuuuuuuuuuuuu", // bcrypt hash
		PasswordResetToken: "reset-token-abc123",
		TwoFactorSecret:    "JBSWY3DPEHPK3PXP", // TOTP secret
		Role:               "user",
		IsAdmin:            false,
		SSN:                "123-45-6789",
		FullCreditCard:     "4111111111111111",
		InternalNotes:      "Flagged for suspicious activity",
		FailedLoginCount:   3,
		IsLocked:           false,
	}
	json.NewEncoder(w).Encode(user)
}

// ─────────────────────────────────────────────
// [LOW] MISSING RATE LIMITING
// ─────────────────────────────────────────────

var loginAttempts = map[string]int{}
var loginMu sync.Mutex

// handleLoginNoRateLimit handles login with no rate limiting — brute force possible.
func handleLoginNoRateLimit(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// ❌ VULN: no rate limiting, no lockout, no CAPTCHA — unlimited brute force attempts
	if username == "admin" && password == "admin123" {
		fmt.Fprintln(w, "Login successful")
		return
	}

	// ❌ VULN: no account lockout even after tracking attempts
	loginMu.Lock()
	loginAttempts[username]++
	attempts := loginAttempts[username]
	loginMu.Unlock()

	// ❌ VULN: user enumeration — different error for non-existent vs. wrong password
	if attempts > 100 {
		http.Error(w, "Too many attempts for user: "+username, 429)
	} else {
		http.Error(w, "Invalid password for user: "+username, 401) // ← leaks user exists
	}
}

// handlePasswordReset has no rate limiting — allows mass token enumeration.
func handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	// ❌ VULN: no rate limiting — attacker enumerates all emails to check registration
	// ❌ VULN: different response for registered vs. unregistered email (user enumeration)
	if isRegisteredEmail(email) {
		fmt.Fprintln(w, "Reset email sent to "+email)
	} else {
		http.Error(w, "No account found for email: "+email, 404)
	}
}

func isRegisteredEmail(email string) bool {
	return email == "admin@example.com" || email == "user@example.com"
}

// ─────────────────────────────────────────────
// [LOW] CACHE CONTROL MISCONFIGURATION
// ─────────────────────────────────────────────

// handleDashboard serves a private dashboard without cache-control headers.
func handleDashboard(w http.ResponseWriter, r *http.Request) {
	// ❌ VULN: no Cache-Control header — browser caches the authenticated page
	// A shared computer user can view cached authenticated content after logout
	// Should set: Cache-Control: no-store, Pragma: no-cache
	fmt.Fprintln(w, `<html><body><h1>Private Dashboard</h1>
		<p>Account balance: $50,000</p>
		<p>SSN: 123-45-6789</p>
	</body></html>`)
}

// handleStaticAsset serves a CSS file with an overly permissive cache policy
// that also inadvertently caches a page containing dynamic user data.
func handleStaticAsset(w http.ResponseWriter, r *http.Request) {
	// ❌ VULN: max-age=31536000 (1 year) applied to what turns out to be a dynamic endpoint
	w.Header().Set("Cache-Control", "public, max-age=31536000")
	w.Header().Set("Expires", time.Now().Add(365*24*time.Hour).UTC().Format(http.TimeFormat))
	fmt.Fprintln(w, "body { color: red; }")
}

// ─────────────────────────────────────────────
// [LOW] MIME TYPE SNIFFING
// ─────────────────────────────────────────────

// serveUserContent serves user-uploaded content without setting Content-Type.
// VULNERABLE: browser will sniff the content type — if user uploads an HTML file
// named "image.jpg", the browser may execute it as HTML.
func serveUserContent(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	content := []byte("<script>alert('XSS via MIME sniffing')</script>")

	// ❌ VULN 1: Content-Type not set → browser sniffs and may execute as HTML
	// ❌ VULN 2: X-Content-Type-Options: nosniff NOT set
	// ❌ VULN 3: filename used directly (path traversal — also shown in file 04)
	_ = filename
	w.Write(content)
}

// ─────────────────────────────────────────────
// [LOW] MISSING CSRF PROTECTION
// ─────────────────────────────────────────────

// handleTransferFunds processes a funds transfer with no CSRF token.
func handleTransferFunds(w http.ResponseWriter, r *http.Request) {
	// ❌ VULN: state-changing POST request with no CSRF token verification
	// An attacker can embed a form on evil.com that auto-submits to this endpoint
	// using the victim's session cookie.
	to := r.FormValue("to_account")
	amount := r.FormValue("amount")
	fmt.Fprintf(w, "Transferred %s to account %s", amount, to)
}

// handleUpdateSettings changes user settings without CSRF protection.
func handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	// ❌ VULN: no CSRF token, no SameSite cookie (see file 02) — CSRF possible
	email := r.FormValue("new_email")
	_ = email
	// Also: no re-authentication required for sensitive changes (should prompt for password)
	fmt.Fprintln(w, "Settings updated")
}

// ─────────────────────────────────────────────
// [LOW] INSECURE DIRECT OBJECT REFERENCE IN EXPORT
// ─────────────────────────────────────────────

// exportReport allows downloading any report by numeric ID — no ownership check.
func exportReport(w http.ResponseWriter, r *http.Request) {
	reportID := r.URL.Query().Get("report_id")
	// ❌ VULN: any authenticated user can download any report — no ownership check
	// (IDOR — also demonstrated in file 02 but at a lower-impact level here)
	filePath := fmt.Sprintf("/var/app/reports/%s.csv", reportID)
	http.ServeFile(w, r, filePath)
}

// ─────────────────────────────────────────────
// [LOW] CLICKJACKING (missing X-Frame-Options)
// ─────────────────────────────────────────────

// handlePaymentPage serves the payment page without clickjacking protection.
func handlePaymentPage(w http.ResponseWriter, r *http.Request) {
	// ❌ VULN: no X-Frame-Options or CSP frame-ancestors directive
	// Attacker can iframe this page on their site and overlay transparent UI to trick clicks
	fmt.Fprintln(w, `<html><body>
		<form method="post" action="/transfer">
			<input name="to_account" value="attacker_account">
			<input name="amount" value="1000">
			<button>Confirm Payment</button>
		</form>
	</body></html>`)
}

// ─────────────────────────────────────────────
// [LOW] SENSITIVE COMMENTS IN SOURCE (also affects built binary strings)
// ─────────────────────────────────────────────

// TODO: remove before production — internal admin bypass:
// If X-Debug-User header is set to "superadmin", skip all auth checks.
// This is still present and active below:

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ❌ VULN: hidden backdoor in auth middleware — header bypass
		if r.Header.Get("X-Debug-User") == "superadmin" {
			next(w, r)
			return
		}
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "unauthorized", 401)
			return
		}
		next(w, r)
	}
}

// ─────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────

func main() {
	mux := http.NewServeMux()

	// Register vulnerable routes (no security middleware applied)
	mux.HandleFunc("/", versionMiddleware(insecureHandler))
	mux.HandleFunc("/api/user", corsMiddleware(getUserAPI))
	mux.HandleFunc("/db-error", handleDBRequest)
	mux.HandleFunc("/panic", handlePanic)
	mux.HandleFunc("/validate", handleValidation)
	mux.HandleFunc("/login", handleLoginNoRateLimit)
	mux.HandleFunc("/reset-password", handlePasswordReset)
	mux.HandleFunc("/dashboard", handleDashboard)
	mux.HandleFunc("/static/style.css", handleStaticAsset)
	mux.HandleFunc("/content", serveUserContent)
	mux.HandleFunc("/transfer", handleTransferFunds)
	mux.HandleFunc("/settings", handleUpdateSettings)
	mux.HandleFunc("/report/export", exportReport)
	mux.HandleFunc("/payment", handlePaymentPage)

	// ❌ VULN: debug routes registered on the main production mux
	registerDebugRoutes(mux)

	log.Printf("[LOW VULNS] Server v%s starting on :8084 (NO TLS)", AppVersion)
	// ❌ VULN: HTTP not HTTPS — all traffic in cleartext, no HSTS possible
	if err := http.ListenAndServe(":8084", mux); err != nil {
		log.Fatal(err)
	}
}
