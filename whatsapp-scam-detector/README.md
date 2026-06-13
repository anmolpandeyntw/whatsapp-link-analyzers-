# 🛡️ WhatsApp Scam Detector

AI-powered + Rule-based WhatsApp scam detection system built with Java Spring Boot.

Forward any suspicious message → Get instant risk analysis!

---

## 🏗️ Architecture

```
User (WhatsApp) 
    → Twilio API 
        → POST /webhook/whatsapp
            → WhatsAppWebhookController
                ├── RuleBasedDetector   (keywords + patterns)
                ├── LinkAnalyzer        (5-layer URL analysis)
                ├── GeminiAIService     (Google Gemini AI)
                ├── SafetyAdvisor       (contextual advice)
                └── ScamDetectionService (combines all → final score)
            → Response (TwiML)
        → Twilio API
    → User (WhatsApp)
```

---

## 📁 Project Structure

```
src/main/java/com/scamdetector/
├── ScamDetectorApplication.java      ← Main entry point
│
├── controller/
│   ├── WhatsAppWebhookController.java ← Twilio webhook (POST /webhook/whatsapp)
│   └── ApiController.java             ← REST API for Postman testing
│
├── service/
│   ├── ScamDetectionService.java      ← Orchestrates all layers
│   ├── RuleBasedDetector.java         ← Keyword + pattern engine
│   ├── LinkAnalyzer.java              ← 5-layer URL analysis
│   ├── GeminiAIService.java           ← Google Gemini integration
│   ├── SafetyAdvisor.java             ← Contextual advice generator
│   ├── UserService.java               ← User CRUD
│   └── ScanService.java               ← Scan logging + history
│
├── model/
│   ├── User.java                      ← User entity
│   └── Scan.java                      ← Scan result entity
│
├── repository/
│   ├── UserRepository.java
│   └── ScanRepository.java
│
├── dto/
│   └── ScamAnalysisResult.java        ← Analysis result DTO
│
├── util/
│   ├── LinkUtils.java                 ← URL extraction + helpers
│   └── ResponseBuilder.java           ← WhatsApp message formatter
│
└── config/
    └── GlobalExceptionHandler.java    ← Error handling
```

---

## ⚙️ Setup & Configuration

### 1. Prerequisites

- Java 17+
- Maven 3.8+
- MySQL 8.0+ (or use H2 for testing)
- Google Gemini API Key (free at: https://aistudio.google.com)
- Twilio Account (free sandbox at: https://twilio.com)

### 2. Environment Variables

Set these before running:

```bash
# Required
export GEMINI_API_KEY=your-gemini-api-key
export DB_URL=jdbc:mysql://localhost:3306/scam_detector?createDatabaseIfNotExist=true&useSSL=false&serverTimezone=UTC
export DB_USERNAME=root
export DB_PASSWORD=yourpassword

# Twilio (for WhatsApp integration)
export TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxx
export TWILIO_AUTH_TOKEN=your-auth-token
```

### 3. Run Locally

```bash
# Clone / navigate to project
cd whatsapp-scam-detector

# Run
mvn spring-boot:run

# Server starts at http://localhost:8080
```

### 4. Run Tests

```bash
mvn test
```

---

## 🧪 Testing with Postman

### Step 1: Test REST API (no Twilio needed)

**POST** `http://localhost:8080/api/analyze`

```json
{
  "message": "URGENT! You have won ₹50,000! Click http://bit.ly/claim123 and enter your OTP now!"
}
```

Expected response:
```json
{
  "riskScore": 87,
  "riskLevel": "HIGH",
  "reasons": [
    "Scam keywords detected: won, win",
    "Urgency manipulation detected: urgent",
    "Sensitive data requested: otp",
    "URL shortener used — hides real destination"
  ],
  "aiInsight": "Classic lottery phishing scam combining urgency and OTP harvesting",
  "safetyAdvice": [
    "Do NOT click any links in this message",
    "NEVER share OTP, PIN, or password with anyone",
    "Block this number immediately"
  ]
}
```

### Step 2: Simulate Twilio Webhook

**POST** `http://localhost:8080/webhook/whatsapp`

Content-Type: `application/x-www-form-urlencoded`

Body (form-encoded):
```
Body=You have won a lottery click bit.ly/fake123 enter OTP now!
From=whatsapp:+919876543210
```

---

## 📱 Twilio WhatsApp Setup

### 1. Create Twilio Account
- Go to https://twilio.com/try-twilio
- Create free account

### 2. Setup WhatsApp Sandbox
- Twilio Console → Messaging → Try it Out → WhatsApp
- Note your sandbox number

### 3. Connect Sandbox to Your Webhook
- In Twilio sandbox settings
- Set webhook URL: `https://your-domain.com/webhook/whatsapp`
- Method: POST

### 4. Expose Local Server (for development)
```bash
# Using ngrok
ngrok http 8080

# Copy the HTTPS URL and set in Twilio
```

### 5. Join Sandbox
- WhatsApp your Twilio sandbox number
- Send the join code shown in Twilio console

### 6. Test!
- Forward any suspicious message to the sandbox number
- Receive instant analysis

---

## 🔍 What It Detects

### Rule-Based Detection
| Category | Examples |
|----------|----------|
| Scam Keywords | lottery, prize, winner, congratulations, jackpot |
| Urgency Keywords | urgent, act now, limited time, expire, hurry |
| Sensitive Keywords | OTP, password, KYC, bank account, CVV, PIN |
| Financial Keywords | loan, investment, earn money, guaranteed profit |
| Threat Keywords | account blocked, legal action, court notice, FIR |
| Phishing Keywords | verify account, click here, download, install APK |

### Link Analysis (5 Layers)
1. **URL Extraction** — finds all http/https links
2. **Domain TLD Check** — flags .xyz, .tk, .ru, .ml etc.
3. **Short Link Detection** — bit.ly, tinyurl, goo.gl etc.
4. **Phishing Patterns** — @ symbol, excessive subdomains, long URLs
5. **Brand Impersonation** — paytm-secure.xyz, amaz0n.com etc.

### AI Analysis (Google Gemini)
- Classifies as LOW / MEDIUM / HIGH
- Provides confidence percentage
- Gives one-line human-readable reason
- Falls back to rule-only if AI unavailable

---

## 💬 User Commands

| User sends | Bot responds |
|------------|-------------|
| Any suspicious message | Full scam analysis |
| `history` | Last 5 scans |
| `help` | Usage guide |
| `hi` / `hello` | Welcome + guide |
| `I clicked the link` | Emergency response |

---

## 📊 Risk Scoring

```
Final Score = (Rule Score × 40%) + (Link Score × 35%) + (AI Score × 25%)

LOW    → 0-40  points
MEDIUM → 41-70 points
HIGH   → 71-100 points
```

### Combination Bonuses
- Scam Keywords + Urgency → +20 bonus
- Sensitive Data + URL → +25 bonus
- Threats + Urgency → +20 bonus
- Financial Scheme + URL → +20 bonus

---

## 🚀 Deployment

### Deploy on Render

1. Push code to GitHub
2. Create new Web Service on Render
3. Build command: `mvn clean package -DskipTests`
4. Start command: `java -jar target/whatsapp-scam-detector-1.0.0.jar`
5. Add environment variables in Render dashboard

### Deploy with Docker

```bash
# Build image
docker build -t scam-detector .

# Run with environment variables
docker run -p 8080:8080 \
  -e GEMINI_API_KEY=your-key \
  -e DB_URL=jdbc:mysql://host:3306/scam_detector \
  -e DB_USERNAME=root \
  -e DB_PASSWORD=password \
  scam-detector
```

---

## 🔮 Future Enhancements (Design Ready)

- **Image Analysis** — OCR + AI to detect scam screenshots
- **File Scanning** — VirusTotal API for APK/PDF scanning
- **Dashboard UI** — Web interface for admins to view scan stats
- **Multi-language** — Hindi, Tamil, Telugu support
- **Real-time Alerts** — Notify admin for HIGH risk messages
- **URL Unshortening** — Follow redirects to see actual destination

---

## 🛡️ Emergency Contacts

- **National Cybercrime Helpline**: 1930
- **Online Reporting**: cybercrime.gov.in
- **RBI Banking Fraud**: 14440

---

Built with ❤️ to fight online scams in India.
