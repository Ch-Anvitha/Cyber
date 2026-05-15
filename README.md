# 🛡️ PRAWL — Know Before They Do

AI-powered web security scanner built for Indian small businesses and developers.
Scan any website for vulnerabilities in 30 seconds. Free. No security team needed.

---

## 🔍 Overview

PRAWL (Penetration & Risk Assessment Web Linter) is an open-source security 
audit tool that detects vulnerabilities, misconfigurations, and data breaches 
across any website — then explains every issue in plain English using AI.

Built with Indian small business owners and developers in mind. No technical background required.

---

## ✨ Features

- SSL Certificate Validation — checks validity and expiry
- Security Headers Analysis — audits 6 critical HTTP headers
- HTTPS Redirect Check — ensures HTTP → HTTPS enforcement
- Open Port Scanner — detects exposed database and service ports
- Data Breach History — powered by HaveIBeenPwned API
- Software Version Disclosure — detects version leaks in headers
- AI-Powered Analysis — Groq/Llama 3.3 70B generates plain-English summaries
- Score History Tracking — SQLite database with Chart.js visualization
- AI Chatbot — ask questions about your scan results
- PDF Report Export — download a professional security audit report

---

## 🛠️ Tech Stack

| Layer      | Technology                                      |
|------------|-------------------------------------------------|
| Backend    | Python, Flask, Flask-Limiter, Flask-CORS        |
| AI         | Groq (Llama 3.3 70B)
| Database   | SQLite                                          |
| PDF        | ReportLab                                       |
| Frontend   | HTML, CSS, JavaScript, Chart.js                 |
| Security   | Python ssl, socket, requests                    |

---

## 📊 Risk Scoring

| Score   | Risk Level | Indicator |
|---------|------------|-----------|
| 80 – 95 | LOW        | 🟢 Green  |
| 60 – 79 | MEDIUM     | 🟡 Yellow |
| 40 – 59 | HIGH       | 🟠 Orange |
| 0 – 39  | CRITICAL   | 🔴 Red    |

---

## 🤖 AI Provider Chain

The chatbot and summary generator attempt providers in this order:

1. Groq — Llama 3.3 70B (free)
2.. Rule-based fallback — always works, no API key required

---

## ⚙️ Installation

### 1. Clone the repository

git clone https://github.com/Ch-Anvitha/Cyber.git
cd Cyber

### 2. Configure environment variables

copy .env.example .env

Open .env and add your API key:

GROQ_API_KEY=your_groq_key_here

Get a free Groq API key at: https://console.groq.com

### 3. Install dependencies

pip install -r requirements.txt

### 4. Run the application

cd backend
python app.py

Or double-click run.bat on Windows.

### 5. Open in browser

http://localhost:5000

---

## 🔑 Environment Variables

| Variable            | Required       | Description                        |
|---------------------|----------------|------------------------------------|
| GROQ_API_KEY        | ✅ Recommended | Free AI summaries via Groq/Llama   |
| ANTHROPIC_API_KEY   | ❌ Optional    | Claude AI (paid, higher quality)   |
| OPENROUTER_API_KEY  | ❌ Optional    | OpenRouter fallback (free tier)    |
| FLASK_DEBUG         | ❌ Optional    | Set true for development only      |
| ALLOWED_ORIGINS     | ❌ Optional    | CORS origins for production        |

---

## 🏗️ Project Structure

Cyber/
├── backend/
│   ├── app.py                 # Flask server and API routes
│   ├── scanner.py             # All security scan modules
│   ├── chatbot.py             # AI chatbot with provider fallback chain
│   ├── report_generator.py    # PDF report generation
│   ├── prawl_history.db       # SQLite scan history (auto-created)
│   └── reports/               # Generated PDFs saved here
├── frontend/
│   ├── templates/
│   │   └── index.html         # Main UI
│   └── static/                # CSS, JS, images
├── requirements.txt
├── run.bat                    # Windows one-click launcher
└── .env                       # API keys — never commit this file

---

## 🔒 Security & Ethics

- Only scan websites you own or have explicit written permission to test
- Rate limited to 5 scans per minute per IP address
- Reports stored locally in backend/reports/
- Never commit your .env file to version control
- This tool is intended for defensive security and authorized auditing only

---

## 👩‍💻 Author

Anvitha Chirumamilla 
GitHub: github.com/Ch-Anvitha
Built as part of Hackathon 2026 

---
## 📄 License

This project is for educational and authorized security testing purposes only.
All rights reserved © Anvitha Chirumamilla, 2026.

> "Security is not a product, but a process." — Bruce Schneier

