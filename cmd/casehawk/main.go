package main

import (
    "log"
    "net/http"
    "os"

    "github.com/hunterkritik-byte/CaseHawk/internal/api"
    "github.com/hunterkritik-byte/CaseHawk/internal/store"
)

func main() {
    addr := getenv("CASEHAWK_ADDR", ":8080")
    dsn := getenv("CASEHAWK_DATABASE_URL", "postgres://casehawk:casehawk@localhost:5432/casehawk?sslmode=disable")
    dataDir := getenv("CASEHAWK_DATA_DIR", "./data/evidence")
	token := os.Getenv("CASEHAWK_API_TOKEN")

    db, err := store.Open(dsn)
    if err != nil { log.Fatalf("database: %v", err) }
    defer db.Close()
    if err := store.Migrate(db); err != nil { log.Fatalf("migration: %v", err) }

    log.Printf("CaseHawk API listening on %s", addr)
    if err := http.ListenAndServe(addr, api.New(db, dataDir, "")); err != nil { log.Fatal(err) }
}

func getenv(k, fallback string) string {
    if v := os.Getenv(k); v != "" { return v }
    return fallback
}
