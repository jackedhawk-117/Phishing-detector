# 🎣 Phishing Detector

A Spring Boot web application that uses **Groq's LLM API** (Llama 3.1) to detect phishing emails in real-time. Secured with **Auth0 OAuth2** login.

## Prerequisites

- **Java 17+**
- **Maven 3.8+** (or use the included `./mvnw` wrapper)
- **Groq API Key** — get one free at [console.groq.com/keys](https://console.groq.com/keys)
- **Auth0 Account** — for OAuth2 authentication (already configured)

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/jackedhawk-117/Phishing-detector.git
cd Phishing-detector
```

### 2. Set up your Groq API key

Create a `.env` file in the project root:

```bash
echo "GROQ_API_KEY=your_groq_api_key_here" > .env
```

> ⚠️ The `.env` file is gitignored and should **never** be committed.

### 3. Run the application

**Linux / macOS:**
```bash
export $(cat .env | xargs) && ./mvnw spring-boot:run
```

**Windows (PowerShell):**
```powershell
$env:GROQ_API_KEY = (Get-Content .env | ForEach-Object { $_.Split('=',2)[1] })
.\mvnw.cmd spring-boot:run
```

### 4. Open in browser

Navigate to [http://localhost:8080](http://localhost:8080)

You'll be redirected to Auth0 for login, then brought to the phishing detector interface.

## How It Works

1. **Login** via Auth0 (Google/GitHub/Email)
2. **Paste** a suspicious email into the text area
3. **Click Analyze** — the email is sent to Groq's Llama 3.1 LLM
4. **Get results** — verdict (phishing/legitimate), confidence level (HIGH/MEDIUM/LOW), and reasoning

## Project Structure

```
src/main/java/com/example/phishingdetector/
├── config/
│   └── SecurityConfig.java          # OAuth2 + Spring Security config
├── controller/
│   └── PhishingController.java      # REST API endpoints
├── model/
│   └── PhishingResult.java          # Response POJO
├── service/
│   ├── GroqPhishingService.java     # Groq LLM API integration
│   ├── FeedbackService.java         # User feedback logging
│   └── PrivacyService.java          # PII anonymization
└── util/
    └── EmailFeatureExtractor.java   # Local feature extraction
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/phishing/detect` | Analyze an email for phishing |
| `POST` | `/api/phishing/feedback` | Submit feedback on a prediction |
| `GET`  | `/api/phishing/user` | Get current user info |

## Configuration

All config lives in `src/main/resources/application.properties`:

| Property | Description |
|----------|-------------|
| `groq.api.key` | Groq API key (read from `GROQ_API_KEY` env var) |
| `groq.model` | LLM model to use (default: `llama-3.1-8b-instant`) |
| `groq.api.url` | Groq API endpoint |

## Tech Stack

- **Backend:** Spring Boot 3.5.3, Java 17
- **AI:** Groq API (Llama 3.1 8B)
- **Auth:** Auth0 OAuth2 / OIDC
- **HTTP Client:** Spring WebFlux (WebClient)
- **Frontend:** Vanilla HTML/CSS/JS (terminal-style UI)
