@echo off
rem --------------------------------------------------
rem Run CyberShield (Windows CMD)
rem --------------------------------------------------

rem 1) Ensure we are in the project root (folder containing this .bat file)
cd /d "%~dp0"

rem 2) Create virtualenv if missing
if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    python -m venv .venv
)

rem 3) Activate venv
call ".venv\Scripts\activate.bat"

rem 4) Install/update dependencies
pip install -r requirements.txt

rem 5) (Optional) Set your AI key here
rem set ANTHROPIC_API_KEY=your_api_key_here

rem 6) Run the web app
cd backend
python app.py

pause
