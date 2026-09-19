package main

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
)

type Breach struct {
    Email    string       `json:"email"`
    Breaches int          `json:"breaches"`
    Services []string     `json:"services"`
    Password PasswordStat `json:"password"`
    Risk     Risk         `json:"risk"`
}

type Anal struct {
    Email           string
    BreachCount     int
    ServiceCount    int
    RiskLevel       string
    RiskScore       int
    PasswordStatus  string
    Recommendations []string
}

type Risk struct {
    Score int    `json:"score"`
    Level string `json:"level"`
}

type PasswordStat struct {
    Plain_text  int `json:"plain_text"`
    Weak_hash   int `json:"weak_hash"`
    Strong_hash int `json:"strong_hash"`
    Total       int `json:"total"`
}

type ProcessedData struct {
    Email         string
    Breaches      int
    Services      []string
    PasswordStats PasswordStat
    RiskScore     int
    RiskLevel     string
}

func collectEmailData(email string) ([]byte, error) {
    req, err := http.NewRequest("GET",
        fmt.Sprintf("https://hackmyip.com/api/breach?email=%s", email), nil)
    if err != nil {
        return nil, fmt.Errorf("error creating request: %v", err)
    }

    req.Header.Set("User-Agent", "Go-http-client/1.1")

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("error making request: %v", err)
    }
    defer resp.Body.Close()

    switch resp.StatusCode {
    case 200:
        // OK
    case 400:
        return nil, fmt.Errorf("bad request — invalid email")
    case 401:
        return nil, fmt.Errorf("unauthorized")
    case 403:
        return nil, fmt.Errorf("forbidden")
    case 404:
        return nil, fmt.Errorf("not found")
    case 429:
        return nil, fmt.Errorf("rate limited")
    case 500:
        return nil, fmt.Errorf("server error")
    case 502:
        return nil, fmt.Errorf("bad gateway")
    case 503:
        return nil, fmt.Errorf("service unavailable")
    case 504:
        return nil, fmt.Errorf("gateway timeout")
    default:
        return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
    }

    return io.ReadAll(resp.Body)
}

func ParseEmailData(data []byte) (Breach, error) {
    var emailData Breach
    if err := json.Unmarshal(data, &emailData); err != nil {
        return Breach{}, fmt.Errorf("error parsing email data: %v", err)
    }
    return emailData, nil
}

func processEmailData(data Breach) ProcessedData {
    pro := ProcessedData{
        Email:         data.Email,
        Breaches:      data.Breaches,
        Services:      data.Services,
        PasswordStats: data.Password,
        RiskScore:     data.Risk.Score,
        RiskLevel:     data.Risk.Level,
    }

    switch {
    case data.Risk.Score >= 80:
        pro.RiskLevel = "critical"
    case data.Risk.Score >= 50:
        pro.RiskLevel = "high"
    case data.Risk.Score >= 30:
        pro.RiskLevel = "medium"
    default:
        pro.RiskLevel = "low"
    }
    return pro
}

func AnalyzeData(pro ProcessedData) Anal {
    analysis := Anal{
        Email:        pro.Email,
        BreachCount:  pro.Breaches,
        ServiceCount: len(pro.Services),
        RiskLevel:    pro.RiskLevel,
        RiskScore:    pro.RiskScore,
    }

    switch {
    case pro.PasswordStats.Plain_text > 0:
        analysis.PasswordStatus = "danger"
    case pro.PasswordStats.Weak_hash > 0:
        analysis.PasswordStatus = "warning"
    default:
        analysis.PasswordStatus = "safe"
    }

    if pro.PasswordStats.Plain_text > 0 {
        analysis.Recommendations = append(analysis.Recommendations,
            fmt.Sprintf("🚨 URGENT: %d plain-text passwords exposed", pro.PasswordStats.Plain_text))
    }
    if pro.PasswordStats.Weak_hash > 0 {
        analysis.Recommendations = append(analysis.Recommendations,
            fmt.Sprintf("⚠️  %d weak password hashes exposed", pro.PasswordStats.Weak_hash))
    }
    if pro.RiskScore >= 80 {
        analysis.Recommendations = append(analysis.Recommendations,
            "🚨 CRITICAL: Enable 2FA on all accounts today")
    } else if pro.RiskScore >= 50 {
        analysis.Recommendations = append(analysis.Recommendations,
            "⚠️  HIGH RISK: Review all affected accounts")
    }
    if len(pro.Services) > 0 {
        analysis.Recommendations = append(analysis.Recommendations,
            fmt.Sprintf("📋 Affected services: %v", pro.Services))
    }

    return analysis
}

func display(analysis Anal) {
    fmt.Println("Running breach scanner")
    fmt.Println("==================================================")
    fmt.Printf("Email:          %s\n", analysis.Email)
    fmt.Printf("BreachCount:    %d\n", analysis.BreachCount)
    fmt.Printf("ServiceCount:   %d\n", analysis.ServiceCount)
    fmt.Printf("RiskScore:      %d\n", analysis.RiskScore)
    fmt.Printf("RiskLevel:      %s\n", analysis.RiskLevel)
    fmt.Printf("PasswordStatus: %s\n", analysis.PasswordStatus)
    fmt.Println("Recommendations:")
    for _, r := range analysis.Recommendations {
        fmt.Printf("  - %s\n", r)
    }
}

func main() {
    fmt.Print("Enter email: ")
    var email string
    fmt.Scanln(&email)

    if email == "" {
        fmt.Println("❌ Email required")
        return
    }

    // COLLECT
    raw, err := collectEmailData(email)
    if err != nil {
        fmt.Println("Collect error:", err)
        return
    }

    // PARSE
    data, err := ParseEmailData(raw)
    if err != nil {
        fmt.Println("Parse error:", err)
        return
    }

    // PROCESS
    processed := processEmailData(data)

    // ANALYZE
    analysis := AnalyzeData(processed)

    // DISPLAY
    display(analysis)
}