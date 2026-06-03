package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./app.db")
	if err != nil {
		panic(err)
	}
	db.Exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
	db.Exec("INSERT OR IGNORE INTO users(id, username, password) VALUES(1, 'admin', 'secret123')")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	password := r.URL.Query().Get("password")

	query := "SELECT id FROM users WHERE username='" + username + "' AND password='" + password + "'"
	row := db.QueryRow(query)

	var id int
	if err := row.Scan(&id); err == nil {
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: username,
		})
		fmt.Fprintf(w, "Welcome, "+username)
	} else {
		fmt.Fprintf(w, "Invalid credentials")
	}
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, err := exec.Command("ping", "-c", "1", host).CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
		return
	}
	fmt.Fprintf(w, string(out))
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<html><body><h1>Hello, "+name+"!</h1></body></html>")
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	fmt.Fprintf(w, "Admin panel: all users visible")
	rows, _ := db.Query("SELECT id, username, password FROM users")
	defer rows.Close()
	for rows.Next() {
		var id int
		var uname, pass string
		rows.Scan(&id, &uname, &pass)
		fmt.Fprintf(w, "\nID: %d | User: %s | Pass: %s", id, uname, pass)
	}
}

func main() {
	initDB()
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/admin", adminHandler)
	http.ListenAndServe(":8080", nil)
}
