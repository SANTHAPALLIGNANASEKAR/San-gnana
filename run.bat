@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>&1
if %errorlevel%==0 (
  set PY=py -3
) else (
  where python >nul 2>&1
  if %errorlevel%==0 (
    set PY=python
  ) else (
    echo Python 3.10+ was not found. Install it from https://www.python.org/downloads/
    echo During setup, enable "Add python.exe to PATH".
    pause
    exit /b 1
  )
)

if not exist .venv\Scripts\python.exe (
  %PY% -m venv .venv
)

.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
