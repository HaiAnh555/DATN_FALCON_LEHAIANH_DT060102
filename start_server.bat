@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -m pip install -q -r requirements.txt
python server.py --host 0.0.0.0 --port 5000
pause
