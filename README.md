# 🛡️ PRAWL — Know Before They Do

> AI-powered cybersecurity scanner for Indian small businesses. Free. 30 seconds.

---

## 🚀 What is PRAWL?

PRAWL is a web-based security audit tool that scans any website for vulnerabilities, misconfigurations, and data breaches — then explains every issue in plain English (or Hindi, Telugu, Tamil, and more) using AI.

Built for Indian small business owners who don't have a security team.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔒 SSL Check | Validates certificate, checks expiry |
| 🛡️ Security Headers | Checks 6 critical HTTP headers |
| 🔄 HTTPS Redirect | Ensures HTTP → HTTPS |
| 🔍 Open Port Scan | Detects exposed database/service ports |
| 💾 Data Breach History | HaveIBeenPwned API check |
| 🔖 Software Disclosure | Detects version leaks in headers |
| 🤖 AI Analysis | Groq/Llama generates plain-English summary |
| 🌐 Regional Languages | Summary in Hindi, Telugu, Tamil, Kannada, Marathi, Bengali |
| 📈 Score History | SQLite tracks score over time with chart |
| 💬 AI Chatbot | Ask questions about your scan results |
| 📄 PDF Report | Download a professional security report |

---

## 🏗️ Project Structure

```
Cyber/
├── backend/
│   ├── app.py              # Flask server & API routes
│   ├── scanner.py          # All security scan modules
│   ├── chatbot.py          # AI chatbot (Groq → Anthropic → OpenRouter → Fallback)
│   ├── report_generator.py # PDF report generation
│   ├── prawl_history.db    # SQLite scan history (auto-created)
│   └── reports/            # Generated PDFs saved here
├── frontend/
│   ├── templates/
│   │   └── index.html      # Main UI
│   └── static/             # CSS / JS / images
├── requirements.txt
├── run.bat                  # Windows one-click launcher
└── .env                     # API keys (never commit this)
```

---

## ⚙️ Setup & Installation

### 1. Clone the repository
```bash
git clone https://github.com/Ch-Anvitha/Cyber.git
cd Cyber
```

### 2. Create your `.env` file
```bash
copy .env.example .env
```
Open `.env` and add your API key:
```
GROQ_API_KEY=your_groq_key_here
```
Get a free Groq API key at → https://console.groq.com

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the app
```bash
cd backend
python app.py
```
Or just double-click `run.bat` on Windows.

### 5. Open browser
```
http://localhost:5000
```

---

## 🔑 Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GROQ_API_KEY` | ✅ Recommended | Free AI summaries via Groq/Llama |
| `ANTHROPIC_API_KEY` | ❌ Optional | Claude AI (paid, higher quality) |
| `OPENROUTER_API_KEY` | ❌ Optional | OpenRouter fallback (free tier) |
| `FLASK_DEBUG` | ❌ Optional | Set `true` for development only |
| `ALLOWED_ORIGINS` | ❌ Optional | CORS origins for production |

---

## 📊 Risk Scoring

| Score | Risk Level | Color |
|---|---|---|
| 80 – 95 | LOW | 🟢 Green |
| 60 – 79 | MEDIUM | 🟡 Yellow |
| 40 – 59 | HIGH | 🟠 Orange |
| 0 – 39 | CRITICAL | 🔴 Red |

---

## 🌐 Language Support

PRAWL generates AI summaries in 7 languages:

- English
- हिंदी (Hindi)
- తెలుగు (Telugu)
- தமிழ் (Tamil)
- ಕನ್ನಡ (Kannada)
- मराठी (Marathi)
- বাংলা (Bengali)

---

## 🤖 AI Provider Chain

The chatbot and summary generator try providers in this order:

1. **Groq** (free) — Llama 3.3 70B
2. **Anthropic** (paid) — Claude Sonnet
3. **OpenRouter** (free tier) — Mistral 7B
4. **Rule-based fallback** — always works, no API key needed

---

## 🛠️ Tech Stack

- **Backend** — Python, Flask, Flask-Limiter, Flask-CORS
- **AI** — Groq (Llama 3.3), Anthropic (Claude), OpenRouter (Mistral)
- **Database** — SQLite (scan history)
- **PDF** — ReportLab
- **Frontend** — Vanilla HTML/CSS/JS, Chart.js
- **Security checks** — Python `ssl`, `socket`, `requests`

---

## 🔒 Security Notes

- Only scan websites you own or have explicit permission to test
- Rate limited to 5 scans per minute per IP
- Reports stored locally in `backend/reports/`
- Never commit your `.env` file

---

## 📄 License

Built for Hackathon 2026 · Python + Flask + Groq AI

---

*PRAWL — Know Before They Do* 🛡️
