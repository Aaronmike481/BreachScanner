package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Breach struct {
	Email string `json:"email"`
	Breaches int `json:"breaches"`
	Services []string `json:"services"`
	Password PasswordStat `json:"password"`
	Risk Risk `json:"risk"`
}

type Anal struct {
	Email string
	BreachCount int
	ServiceCount int
	RiskLevel string
	RiskScore int
	 PasswordStatus  string      // ← NEW
    Recommendations []string    // ← NEW
}


type Risk struct {
    Score int    `json:"score"`
    Level string `json:"level"`
}

type PasswordStat struct {
	Plain_text int `json:"plain_text"`
	Weak_hash int `json:"weak_hash"`
	Strong_hash int `json:"strong_hash"`
	Total int `json:"total"`
}
type HackMyIPResponse struct {
    Success bool       `json:"success"`
    Data    Breach `json:"data"`
}


type ProcessedData struct {
	Email string
	Breaches int
	Services []string
	PasswordStats PasswordStat
	RiskScore int
	RiskLevel string
}

func collectEmailData(email string) ([]byte, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://hackmyip.com/api/breach?email=%s", email), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("User-Agent", "Go-http-client/1.1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

 switch resp.StatusCode {
    case 200:
        // OK — continue
    case 400:
        return nil, fmt.Errorf("bad request — invalid email")
    case 401:
        return nil, fmt.Errorf("unauthorized — API key required")
    case 403:
        return nil, fmt.Errorf("forbidden — blocked by API")
    case 404:
        return nil, fmt.Errorf("not found — no data for this email")
    case 429:
        return nil, fmt.Errorf("rate limited — slow down and try later")
    case 500:
        return nil, fmt.Errorf("server error on their side")
    case 502:
        return nil, fmt.Errorf("bad gateway — API may be down")
    case 503:
        return nil, fmt.Errorf("service unavailable — API is down, try later")
    case 504:
        return nil, fmt.Errorf("gateway timeout — API too slow")
    default:
        return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
    }


	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	return body, nil
}


func PareseEmailData(data []byte) (Breach, error){
	var emailData Breach
	if err := json.Unmarshal(data, &emailData); err != nil{
		return Breach{}, fmt.Errorf("error parsing email data: %v", err)
	}
	return emailData, nil
}


func processEmailData(data Breach) ProcessedData {
	pro := ProcessedData{
		Email: data.Email,
		Breaches: data.Breaches,
		Services: data.Services,
		PasswordStats: data.Password,
		RiskScore: data.Risk.Score,
		RiskLevel: data.Risk.Level,
	}

	switch{
	case data.Risk.Score >= 80:
		pro.RiskLevel = "critical"
	case data.Risk.Score >= 50:
		pro.RiskLevel = "high"
	case data.Risk.Score >= 30:
		pro.RiskLevel = "miduim"
	default:
		pro.RiskLevel = "low"
		
	}
	return pro
}

func Analisis(pro ProcessedData) Anal{
analisis := Anal{
	Email: pro.Email,
	BreachCount: pro.Breaches,
	ServiceCount: len(pro.Services),
	RiskLevel: pro.RiskLevel,
		RiskScore: pro.RiskScore,
}


switch{
case pro.PasswordStats.Plain_text > 0:
	analisis.PasswordStatus = "danger"
case pro.PasswordStats.Strong_hash > 0:
	analisis.PasswordStatus = "warning"
default:
     analisis.PasswordStatus = "warning"
}

if pro.PasswordStats.Plain_text > 0{
	analisis.Recommendations = append(analisis.Recommendations, fmt.Sprintf("change password bro - %d exposed", pro.PasswordStats.Plain_text))
}

if pro.PasswordStats.Strong_hash > 0{
	analisis.Recommendations = append(analisis.Recommendations, fmt.Sprintf("dummy text - %d exposed" ,pro.PasswordStats.Strong_hash))
}

return analisis
}


func display(analysis Anal){
	fmt.Println("Runing breach scanner")
	fmt.Println("==================================================")
	fmt.Printf("email: - %s\n", analysis.Email)
	fmt.Printf("breachCount: - %d\n", analysis.BreachCount)
	fmt.Printf("serviceCount: - %d\n", analysis.ServiceCount)
	fmt.Printf("RiskScore: - %d", analysis.RiskScore)
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


fmt.Println("=== RAW RESPONSE ===")
fmt.Println(string(raw))
fmt.Println("====================")

    // PARSE
    data, err := PareseEmailData(raw)
    if err != nil {
        fmt.Println("Parse error:", err)
        return
    }

    // PROCESS
    processed := processEmailData(data)

    // ANALYZE
    analysis := Analisis(processed)

    // DISPLAY
    display(analysis)
}