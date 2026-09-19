package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "strings"
)

func handleCheck(w http.ResponseWriter, r *http.Request) {
    email := strings.TrimSpace(r.URL.Query().Get("email"))
    if email == "" {
        http.Error(w, "email query parameter required", http.StatusBadRequest)
        return
    }

    // COLLECT
    raw, err := collectEmailData(email)
    if err != nil {
        http.Error(w, fmt.Sprintf("collect error: %v", err), http.StatusInternalServerError)
        return
    }

    // PARSE
    data, err := ParseEmailData(raw)
    if err != nil {
        http.Error(w, fmt.Sprintf("parse error: %v", err), http.StatusInternalServerError)
        return
    }

    // PROCESS
    processed := processEmailData(data)

    // ANALYZE
    analysis := AnalyzeData(processed)

    // RESPOND
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(analysis)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
    fmt.Fprint(w, "ok")
}

func main() {
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }

    http.HandleFunc("/check", handleCheck)
    http.HandleFunc("/health", handleHealth)

    fmt.Printf("🚀 Server running on port %s\n", port)
    log.Fatal(http.ListenAndServe("0.0.0.0:"+port, nil))
}