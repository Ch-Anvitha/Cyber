# 🛡️ CyberShield — AI Cybersecurity Copilot

**Instant security audits for Indian small businesses. Free. 30 seconds.**

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Set API Key (Optional — for AI summaries)
```bash
export ANTHROPIC_API_KEY=your_key_here
```

### 3. Run the App
```bash
cd backend
python app.py
```

### 4. Open Browser
Navigate to: **http://localhost:5000**

---

## 🏗️ Project Structure
```
cybershield/
├── backend/
│   ├── app.py              # Flask server & API routes
│   ├── scanner.py          # All security scan modules
│   ├── report_generator.py # PDF report generation
│   └── reports/            # Generated PDFs saved here
├── frontend/
│   ├── templates/
│   │   └── index.html      # Main UI (single file)
│   └── static/             # CSS/JS/images
└── requirements.txt
```

---

## 🔍 What Gets Scanned

| Check | What It Does |
|-------|-------------|
| SSL Certificate | Validates cert, checks expiry |
| Security Headers | 6 critical HTTP headers |
| HTTPS Redirect | Ensures HTTP → HTTPS |
| Open Ports | Detects exposed database/service ports |
| Data Breach History | HaveIBeenPwned API |
| Software Disclosure | Checks for version leaks in headers |
| AI Analysis | Claude generates plain-English summary |

---

## 🎨 Color Theme
- **Black**: `#030712` (background)
- **Dark Blues**: `#0a0f1e`, `#0d1527` (cards)
- **Electric Blue**: `#0ea5e9` (accent/primary)
- **Grey**: `#94a3b8` (secondary text)

---

## 📊 Risk Scoring
| Score | Risk Level | Color |
|-------|-----------|-------|
| 80-100 | LOW | Green |
| 60-79 | MEDIUM | Yellow |
| 40-59 | HIGH | Orange |
| 0-39 | CRITICAL | Red |

---

## 🔧 Configuration

Edit `backend/scanner.py` to add:
- **HaveIBeenPwned API key** (for breach checks)
- **DeHashed API** (for dark web monitoring)

---

## 💡 Demo Tips (Hackathon)

1. Scan a real local Indian business website on stage
2. Narrate each check as it runs
3. Click the RED findings to show AI explanations
4. Download PDF report live — "₹1 lakh report in 30 seconds"

---

*Built for Hackathon 2026 · Python + Flask + Claude AI*
