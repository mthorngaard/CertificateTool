@echo off
cd /d "%~dp0"
python -c "import cryptography" 2>nul || python -m pip install -r requirements.txt
start "" pythonw app.py
