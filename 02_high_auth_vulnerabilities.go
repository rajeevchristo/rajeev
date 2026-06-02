// FILE: 02_high_auth_vulnerabilities.go
// SEVERITY: HIGH
// VULNERABILITIES COVERED:
//   [HIGH] Hardcoded credentials and secret keys
//   [HIGH] Broken JWT validation (algorithm confusion, "none" alg, no expiry check)
//   [HIGH] Insecure session management (predictable token, no invalidation)
//   [HIGH] Missing authorisation checks (IDOR — Insecure Direct Object Reference)
//   [HIGH] Mass assignment (binding all request fields to internal struct)
//   [HIGH] Cleartext password storage (no hashing)
//   [HIGH] Race condition on session token (TOCTOU)
//
// ⚠️  THIS FILE IS INTENTIONALLY VULNERABLE — FOR SECURITY TRAINING ONLY ⚠️
// DO NOT DEPLOY OR USE IN PRODUCTION

package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────
// [HIGH] HARDCODED CREDENTIALS & SECRET KEYS
// ─────────────────────────────────────────────

const (
	// ❌ VULN: Hardcoded secrets committed to source control
	jwtSecretKey     = "supersecret123"
	adminPassword    = "admin123"
	dbPassword       = "P@ssw0rd!"
	encryptionKey    = "0123456789abcdef" // 16-byte AES key — hardcoded
	stripeSecretKey  = "sk_live_FAKEKEYFORSECURITY1234567890" // payment key in code
	internalAPIToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.hardcoded"
)

// Config holds application secrets — all hardcoded, none read from env.
type Config struct {
	DBHost     string
	DBUser     string
	DBPassword string
	JWTSecret  string
	AdminUser  string
	AdminPass  string
}

// ❌ VULN: default config with production secrets embedded in source
var appConfig = Config{
	DBHost:     "prod-db.internal",
	DBUser:     "root",
	DBPassword: dbPassword,
	JWTSecret:  jwtSecretKey,
	AdminUser:  "admin",
	AdminPass:  adminPassword,
}

// ─────────────────────────────────────────────
// [HIGH] CLEARTEXT PASSWORD STORAGE
// ─────────────────────────────────────────────

// UserRecord stores a user in the in-memory "database".
type UserRecord struct {
	ID       int
	Username string
	Password string // ❌ VULN: stored in plaintext
	Email    string
	Role     string
	IsAdmin  bool
}

var (
	userStore   = map[int]*UserRecord{}
	userStoreMu sync.RWMutex
	nextUserID  = 1
)

// registerUser saves a new user with their password stored in plaintext.
func registerUser(username, password, email string) (*UserRecord, error) {
	userStoreMu.Lock()
	defer userStoreMu.Unlock()

	// ❌ VULN: password stored as-is — should use bcrypt/argon2
	user := &UserRecord{
		ID:       nextUserID,
		Username: username,
		Password: password, // plaintext!
		Email:    email,
		Role:     "user",
	}
	userStore[nextUserID] = user
	nextUserID++
	return user, nil
}

// checkPassword compares passwords in plaintext using == (also timing-oracle vulnerable).
func checkPassword(stored, provided string) bool {
	// ❌ VULN: plain string comparison — no constant-time compare, no hashing
	return stored == provided
}

// ─────────────────────────────────────────────
// [HIGH] BROKEN JWT VALIDATION
// ─────────────────────────────────────────────

// JWTHeader represents a decoded JWT header.
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// JWTClaims represents the JWT body.
type JWTClaims struct {
	Sub      string `json:"sub"`
	Role     string `json:"role"`
	UserID   int    `json:"user_id"`
	IsAdmin  bool   `json:"is_admin"`
	Exp      int64  `json:"exp"` // expiry — but we don't check it (see below)
	IssuedAt int64  `json:"iat"`
}

// generateJWT creates a signed JWT token.
func generateJWT(userID int, username, role string, isAdmin bool) (string, error) {
	header := JWTHeader{Alg: "HS256", Typ: "JWT"}
	claims := JWTClaims{
		Sub:      username,
		Role:     role,
		UserID:   userID,
		IsAdmin:  isAdmin,
		Exp:      time.Now().Add(24 * time.Hour).Unix(),
		IssuedAt: time.Now().Unix(),
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	mac := hmac.New(sha256.New, []byte(jwtSecretKey)) // ❌ hardcoded key
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

// validateJWT validates a JWT — BUT has multiple critical flaws.
func validateJWT(token string) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	var header JWTHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, err
	}

	// ❌ VULN 1: "none" algorithm attack — attacker can strip signature entirely
	if strings.ToLower(header.Alg) == "none" {
		log.Println("[WARN] none algorithm accepted — signature check skipped")
		claimsJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims JWTClaims
		json.Unmarshal(claimsJSON, &claims)
		return &claims, nil // ← no signature verification at all!
	}

	// ❌ VULN 2: algorithm confusion — RS256 public key used as HMAC secret
	// If server also supports RS256, attacker can sign with public key as HMAC key
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(jwtSecretKey))
	mac.Write([]byte(signingInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// ❌ VULN 3: non-constant-time string comparison — timing oracle
	if parts[2] != expectedSig {
		return nil, fmt.Errorf("signature mismatch")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, err
	}

	// ❌ VULN 4: expiry NOT checked — expired tokens accepted forever
	// The correct check would be: if time.Now().Unix() > claims.Exp { return error }

	return &claims, nil
}

// ─────────────────────────────────────────────
// [HIGH] INSECURE SESSION MANAGEMENT
// ─────────────────────────────────────────────

var (
	sessionStore   = map[string]*UserRecord{}
	sessionStoreMu sync.RWMutex
)

// generateSessionToken creates a predictable token using math/rand with time seed.
func generateSessionToken() string {
	// ❌ VULN: math/rand is NOT cryptographically secure; seed is predictable (Unix time)
	rand.Seed(time.Now().UnixNano()) //nolint
	return fmt.Sprintf("%d", rand.Int63())
}

// createSession creates a session with a weak token, no expiry, no HttpOnly cookie.
func createSession(w http.ResponseWriter, user *UserRecord) string {
	token := generateSessionToken()

	sessionStoreMu.Lock()
	sessionStore[token] = user
	sessionStoreMu.Unlock()

	// ❌ VULN: cookie missing Secure, HttpOnly, SameSite flags
	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: token,
		// Secure:   true,   // ← missing — sent over HTTP
		// HttpOnly: true,   // ← missing — accessible to JS (XSS escalation)
		// SameSite: http.SameSiteLaxMode, // ← missing — CSRF risk
		Path: "/",
	})
	return token
}

// getSessionUser retrieves user from session — no rotation after auth.
func getSessionUser(r *http.Request) (*UserRecord, error) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil, fmt.Errorf("no session cookie")
	}
	sessionStoreMu.RLock()
	user, ok := sessionStore[cookie.Value]
	sessionStoreMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("invalid session")
	}
	// ❌ VULN: session never expires, never rotated after privilege change
	return user, nil
}

// logout removes the session from the store but does NOT invalidate the cookie on client.
func logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return
	}
	sessionStoreMu.Lock()
	delete(sessionStore, cookie.Value)
	sessionStoreMu.Unlock()

	// ❌ VULN: cookie not cleared on the client — old token still works if re-sent
	// Should set: MaxAge: -1, Expires: past date
	fmt.Fprintln(w, "Logged out")
}

// ─────────────────────────────────────────────
// [HIGH] INSECURE DIRECT OBJECT REFERENCE (IDOR)
// ─────────────────────────────────────────────

// getProfile returns ANY user's profile if you know their ID — no ownership check.
func getProfile(w http.ResponseWriter, r *http.Request) {
	// ❌ VULN: no check that the requester owns this profile
	idStr := r.URL.Query().Get("user_id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "invalid id", 400)
		return
	}

	userStoreMu.RLock()
	user, ok := userStore[id]
	userStoreMu.RUnlock()

	if !ok {
		http.Error(w, "user not found", 404)
		return
	}

	// ❌ VULN: returns plaintext password to caller!
	json.NewEncoder(w).Encode(user)
}

// updateProfile updates any user's data without verifying identity.
func updateProfile(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("user_id")
	id, _ := strconv.Atoi(idStr)

	// ❌ VULN: no auth check — any authenticated user can edit any other user's record
	var updates map[string]interface{}
	json.NewDecoder(r.Body).Decode(&updates)

	userStoreMu.Lock()
	user, ok := userStore[id]
	if ok {
		// ❌ VULN: mass assignment — attacker can set is_admin=true
		if role, exists := updates["role"]; exists {
			user.Role = fmt.Sprintf("%v", role)
		}
		if isAdmin, exists := updates["is_admin"]; exists {
			user.IsAdmin = isAdmin.(bool) // also panics on wrong type
		}
		if email, exists := updates["email"]; exists {
			user.Email = fmt.Sprintf("%v", email)
		}
	}
	userStoreMu.Unlock()

	if !ok {
		http.Error(w, "user not found", 404)
		return
	}
	fmt.Fprintln(w, "Profile updated")
}

// ─────────────────────────────────────────────
// [HIGH] RACE CONDITION (TOCTOU) ON SESSION
// ─────────────────────────────────────────────

// transferCredits transfers credits between users — classic TOCTOU race.
type Account struct {
	mu      sync.Mutex // ← defined but NOT used in the transfer below
	UserID  int
	Credits int
}

var accounts = map[int]*Account{}

// transferCredits checks balance then deducts — TOCTOU between check and deduct.
func transferCredits(fromID, toID, amount int) error {
	from, ok1 := accounts[fromID]
	to, ok2 := accounts[toID]
	if !ok1 || !ok2 {
		return fmt.Errorf("account not found")
	}

	// ❌ VULN: check and deduct are not atomic — concurrent requests can overdraft
	if from.Credits < amount {
		return fmt.Errorf("insufficient credits")
	}
	// window here — another goroutine may have already spent these credits
	time.Sleep(1 * time.Millisecond) // simulates latency that opens the race window
	from.Credits -= amount
	to.Credits += amount
	return nil
}

// ─────────────────────────────────────────────
// [HIGH] MISSING FUNCTION-LEVEL ACCESS CONTROL
// ─────────────────────────────────────────────

// adminDeleteUser deletes a user — but relies entirely on a request parameter for auth.
func adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	// ❌ VULN: admin check reads from a user-controlled header, not from session/JWT
	isAdmin := r.Header.Get("X-Admin") == "true"
	if !isAdmin {
		http.Error(w, "forbidden", 403)
		return
	}

	idStr := r.URL.Query().Get("user_id")
	id, _ := strconv.Atoi(idStr)

	userStoreMu.Lock()
	delete(userStore, id)
	userStoreMu.Unlock()

	fmt.Fprintf(w, "User %d deleted", id)
}

// ─────────────────────────────────────────────
// [HIGH] WEAK PASSWORD RESET TOKEN (MD5 of email)
// ─────────────────────────────────────────────

// generatePasswordResetToken creates a reset token by MD5-hashing the email + timestamp.
// VULNERABLE: MD5 is broken; timestamp is guessable within a short window.
func generatePasswordResetToken(email string) string {
	// ❌ VULN: MD5 is cryptographically broken; timestamp adds weak entropy
	seed := email + strconv.FormatInt(time.Now().Unix(), 10)
	hash := md5.Sum([]byte(seed)) //nolint:gosec
	return fmt.Sprintf("%x", hash)
}

// resetPassword accepts the token and sets the new password without rate-limiting.
func resetPassword(token, newPassword string) error {
	// ❌ VULN: no rate limiting, no token expiry, no single-use enforcement
	for _, user := range userStore {
		expected := generatePasswordResetToken(user.Email)
		if token == expected {
			userStoreMu.Lock()
			user.Password = newPassword // ❌ still plaintext
			userStoreMu.Unlock()
			return nil
		}
	}
	return fmt.Errorf("invalid token")
}

// ─────────────────────────────────────────────
// HTTP HANDLERS
// ─────────────────────────────────────────────

func handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	user, err := registerUser(body.Username, body.Password, body.Email)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	token, _ := generateJWT(user.ID, user.Username, user.Role, user.IsAdmin)
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	userStoreMu.RLock()
	var found *UserRecord
	for _, u := range userStore {
		if u.Username == username {
			found = u
			break
		}
	}
	userStoreMu.RUnlock()

	if found == nil || !checkPassword(found.Password, password) {
		http.Error(w, "Invalid credentials", 401)
		return
	}

	createSession(w, found)
	fmt.Fprintf(w, "Welcome %s", found.Username)
}

func handleJWTValidate(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := validateJWT(token)
	if err != nil {
		http.Error(w, "invalid token: "+err.Error(), 401)
		return
	}
	json.NewEncoder(w).Encode(claims)
}

func main() {
	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/login", handleAuthLogin)
	http.HandleFunc("/validate", handleJWTValidate)
	http.HandleFunc("/profile", getProfile)
	http.HandleFunc("/profile/update", updateProfile)
	http.HandleFunc("/admin/delete", adminDeleteUser)
	http.HandleFunc("/logout", logout)

	log.Println("[HIGH VULNS] Server on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
