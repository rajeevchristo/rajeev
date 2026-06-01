// FILE: 03_medium_crypto_issues.go
// SEVERITY: MEDIUM-HIGH
// VULNERABILITIES COVERED:
//   [HIGH]   Weak cryptography — DES, RC4, ECB-mode AES
//   [HIGH]   Insecure random number generation (math/rand for security decisions)
//   [MEDIUM] MD5 / SHA-1 used for password hashing
//   [MEDIUM] Static IV / nonce reuse in AES-GCM
//   [MEDIUM] Weak key derivation (no salt, low iterations)
//   [MEDIUM] TLS misconfiguration (InsecureSkipVerify, SSLv3)
//   [MEDIUM] Sensitive data exposure in logs
//   [MEDIUM] Padding oracle (CBC mode without MAC-then-Encrypt)
//
// ⚠️  THIS FILE IS INTENTIONALLY VULNERABLE — FOR SECURITY TRAINING ONLY ⚠️
// DO NOT DEPLOY OR USE IN PRODUCTION

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"   //nolint:gosec — intentionally insecure
	"crypto/md5"   //nolint:gosec — intentionally insecure
	"crypto/rc4"   //nolint:gosec — intentionally insecure
	"crypto/sha1"  //nolint:gosec — intentionally insecure
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"
)

// ─────────────────────────────────────────────
// [HIGH] WEAK CIPHERS — DES AND RC4
// ─────────────────────────────────────────────

// encryptWithDES encrypts data using single DES — 56-bit key, brute-forceable.
// DES was broken in the 1990s. Use AES-256-GCM instead.
func encryptWithDES(key, plaintext []byte) ([]byte, error) {
	// ❌ VULN: DES key is only 56 effective bits; can be brute-forced in hours
	block, err := des.NewCipher(key) //nolint:gosec
	if err != nil {
		return nil, err
	}
	// ❌ VULN: ECB-like manual block encryption — identical blocks produce identical output
	ciphertext := make([]byte, len(plaintext))
	if len(plaintext)%des.BlockSize != 0 {
		return nil, fmt.Errorf("plaintext not block-aligned")
	}
	for i := 0; i < len(plaintext); i += des.BlockSize {
		block.Encrypt(ciphertext[i:i+des.BlockSize], plaintext[i:i+des.BlockSize])
	}
	return ciphertext, nil
}

// decryptWithDES decrypts data using single DES.
func decryptWithDES(key, ciphertext []byte) ([]byte, error) {
	block, err := des.NewCipher(key) //nolint:gosec
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += des.BlockSize {
		block.Decrypt(plaintext[i:i+des.BlockSize], ciphertext[i:i+des.BlockSize])
	}
	return plaintext, nil
}

// encryptWithRC4 encrypts using RC4 — stream cipher with known biases.
// RC4 is prohibited by RFC 7465. Do NOT use for TLS or any data confidentiality.
func encryptWithRC4(key, plaintext []byte) ([]byte, error) {
	// ❌ VULN: RC4 has severe statistical biases; WEP and early TLS were broken by this
	cipher, err := rc4.NewCipher(key) //nolint:gosec
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// ─────────────────────────────────────────────
// [HIGH] AES IN ECB MODE
// ─────────────────────────────────────────────

// encryptAESECB encrypts using AES-ECB — deterministic, leaks patterns.
// Classic visual: encrypt a bitmap image in ECB and the outlines are still visible.
func encryptAESECB(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// ❌ VULN: ECB encrypts each block independently — identical plaintext blocks
	// produce identical ciphertext blocks, revealing data patterns.
	// No IV needed — that's the problem.
	if len(plaintext)%aes.BlockSize != 0 {
		// ❌ VULN: zero-padding (not PKCS#7) — padding oracle risk
		padding := aes.BlockSize - len(plaintext)%aes.BlockSize
		plaintext = append(plaintext, bytes.Repeat([]byte{0}, padding)...)
	}
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:i+aes.BlockSize], plaintext[i:i+aes.BlockSize])
	}
	return ciphertext, nil
}

// ─────────────────────────────────────────────
// [MEDIUM] STATIC IV / NONCE REUSE IN AES-CBC AND AES-GCM
// ─────────────────────────────────────────────

var (
	// ❌ VULN: hardcoded, static IV — same IV used for every encryption operation
	staticIV    = []byte("1234567890123456") // 16 bytes
	staticNonce = []byte("staticnonce!") // 12 bytes for GCM
)

// encryptAESCBCStaticIV encrypts with AES-CBC but reuses the same IV every time.
// Reusing an IV in CBC reveals XOR patterns between messages sharing a prefix.
func encryptAESCBCStaticIV(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// PKCS7 padding
	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	plaintext = append(plaintext, bytes.Repeat([]byte{byte(pad)}, pad)...)

	ciphertext := make([]byte, len(plaintext))
	// ❌ VULN: staticIV is constant — never changes between calls
	mode := cipher.NewCBCEncrypter(block, staticIV)
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// encryptAESGCMStaticNonce encrypts with AES-GCM but reuses the same nonce.
// Nonce reuse in GCM catastrophically breaks confidentiality AND authenticity.
func encryptAESGCMStaticNonce(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// ❌ VULN: same nonce for every message — two-time pad attack recovers plaintext
	return gcm.Seal(nil, staticNonce, plaintext, nil), nil
}

// ─────────────────────────────────────────────
// [MEDIUM] BROKEN PASSWORD HASHING
// ─────────────────────────────────────────────

// hashPasswordMD5 hashes a password using MD5 — trivially rainbow-table attacked.
func hashPasswordMD5(password string) string {
	// ❌ VULN: MD5 is not suitable for password hashing; no salt; precomputed tables exist
	h := md5.Sum([]byte(password)) //nolint:gosec
	return hex.EncodeToString(h[:])
}

// hashPasswordSHA1 hashes a password using SHA-1 — marginally better but still wrong.
func hashPasswordSHA1(password string) string {
	// ❌ VULN: SHA-1 is cryptographically broken (collision attacks); no salt; no stretching
	h := sha1.Sum([]byte(password)) //nolint:gosec
	return hex.EncodeToString(h[:])
}

// hashPasswordUnsaltedSHA256 uses SHA-256 but with no salt — still vulnerable to rainbow tables.
func hashPasswordUnsaltedSHA256(password string) string {
	// ❌ VULN: no salt — identical passwords produce identical hashes; rainbow tables work
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

// weakKDF derives a key with only 100 PBKDF2 iterations and a static salt.
func weakKDF(password, salt string) []byte {
	// ❌ VULN: 100 iterations is orders of magnitude too low (OWASP recommends 600k+ for SHA-256)
	// ❌ VULN: static salt defeats the purpose of salting
	combined := password + salt + "static_salt_hardcoded"
	h := sha256.Sum256([]byte(combined))
	for i := 0; i < 100; i++ { // only 100 rounds — trivially brute-forceable
		h = sha256.Sum256(h[:])
	}
	return h[:]
}

// ─────────────────────────────────────────────
// [HIGH] INSECURE RANDOM FOR SECURITY DECISIONS
// ─────────────────────────────────────────────

// generateOTP generates a 6-digit OTP using math/rand — predictable.
func generateOTP() string {
	// ❌ VULN: math/rand is deterministic given the seed; attacker can predict OTPs
	rand.Seed(time.Now().UnixNano()) //nolint
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

// generateAPIKey creates an API key using math/rand — guessable.
func generateAPIKey() string {
	// ❌ VULN: should use crypto/rand; math/rand output can be predicted
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	key := make([]byte, 32)
	rand.Seed(time.Now().UnixNano()) //nolint
	for i := range key {
		key[i] = charset[rand.Intn(len(charset))]
	}
	return string(key)
}

// generateCSRFToken creates a CSRF token using math/rand — attackers can enumerate tokens.
func generateCSRFToken(userID int) string {
	// ❌ VULN: CSRF token is seeded by time + userID — guessable within a time window
	rand.Seed(time.Now().UnixNano() + int64(userID)) //nolint
	return fmt.Sprintf("%d-%d", userID, rand.Int63())
}

// ─────────────────────────────────────────────
// [MEDIUM] TLS MISCONFIGURATION
// ─────────────────────────────────────────────

// newInsecureHTTPClient creates an HTTP client that skips TLS certificate verification.
func newInsecureHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// ❌ VULN: accepting any cert — MITM trivially possible
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
	}
}

// newWeakTLSServer starts an HTTPS server with weak TLS settings.
func newWeakTLSServer(addr, certFile, keyFile string) *http.Server {
	return &http.Server{
		Addr: addr,
		TLSConfig: &tls.Config{
			// ❌ VULN: MinVersion not set — defaults to TLS 1.0 in older Go versions
			// ❌ VULN: enabling weak cipher suites
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_RC4_128_SHA,      // RC4 — broken
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, // 3DES — deprecated
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,  // no forward secrecy
			},
			// ❌ VULN: client cert verification disabled
			ClientAuth: tls.NoClientCert,
		},
	}
}

// fetchURLInsecure fetches a URL ignoring TLS errors — common copy-paste antipattern.
func fetchURLInsecure(url string) ([]byte, error) {
	client := newInsecureHTTPClient()
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	return buf.Bytes(), nil
}

// ─────────────────────────────────────────────
// [MEDIUM] SENSITIVE DATA IN LOGS
// ─────────────────────────────────────────────

// processPayment logs sensitive card data to standard logger.
func processPayment(cardNumber, cvv, expiry, amount string) error {
	// ❌ VULN: PCI-DSS violation — card data written to log files
	log.Printf("[PAYMENT] Processing card=%s cvv=%s expiry=%s amount=%s",
		cardNumber, cvv, expiry, amount)

	// ❌ VULN: if logging framework ships logs to external SIEM, this is a breach
	fmt.Printf("DEBUG: Full card details: %s / %s / %s\n", cardNumber, cvv, expiry)
	return nil
}

// loginWithLogging logs credentials before authenticating.
func loginWithLogging(username, password string) bool {
	// ❌ VULN: passwords in log files
	log.Printf("[AUTH] Login attempt: username=%s password=%s", username, password)
	return username == "admin" && password == "admin123"
}

// storeTokenInURL stores auth token as a URL query parameter — logs and referer headers leak it.
func storeTokenInURL(w http.ResponseWriter, r *http.Request) {
	token := generateAPIKey()
	// ❌ VULN: token in URL appears in server access logs, browser history, referer headers
	http.Redirect(w, r, "/dashboard?token="+token, http.StatusFound)
}

// ─────────────────────────────────────────────
// [MEDIUM] CBC PADDING ORACLE (VULNERABLE DECRYPT)
// ─────────────────────────────────────────────

// decryptAESCBC decrypts AES-CBC and returns a different error for padding failures.
// VULNERABLE: distinct error messages for padding vs. MAC failure enable padding oracle attacks.
func decryptAESCBC(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		// ❌ VULN: distinct error — "invalid length" vs. "bad padding" leaks oracle info
		return nil, fmt.Errorf("invalid ciphertext length")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// ❌ VULN: padding error returned separately from auth error
	pad := int(plaintext[len(plaintext)-1])
	if pad == 0 || pad > aes.BlockSize {
		return nil, fmt.Errorf("bad padding") // oracle: tells attacker padding is wrong
	}
	for i := len(plaintext) - pad; i < len(plaintext); i++ {
		if int(plaintext[i]) != pad {
			return nil, fmt.Errorf("bad padding") // same distinct error
		}
	}
	return plaintext[:len(plaintext)-pad], nil
}

// ─────────────────────────────────────────────
// HTTP HANDLERS
// ─────────────────────────────────────────────

func handleEncrypt(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("data")
	key := []byte("hardcodedkey1234") // ❌ hardcoded key
	ct, err := encryptAESECB(key, []byte(data))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, "%x", ct)
}

func handleOTP(w http.ResponseWriter, r *http.Request) {
	otp := generateOTP()
	// ❌ VULN: OTP returned in response AND logged
	log.Printf("Generated OTP: %s", otp)
	fmt.Fprintln(w, otp)
}

func handleAPIKey(w http.ResponseWriter, r *http.Request) {
	key := generateAPIKey()
	fmt.Fprintln(w, key)
}

func main() {
	http.HandleFunc("/encrypt", handleEncrypt)
	http.HandleFunc("/otp", handleOTP)
	http.HandleFunc("/apikey", handleAPIKey)
	http.HandleFunc("/token-redirect", storeTokenInURL)

	log.Println("[MEDIUM-HIGH CRYPTO VULNS] Server on :8082")
	log.Fatal(http.ListenAndServe(":8082", nil))
}
