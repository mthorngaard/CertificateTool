@echo off
cd /d "%~dp0"

rem Prefer "python"; fall back to the "py" launcher if python is not on PATH
set "PY=python"
set "PYW=pythonw"
where python >nul 2>nul || (
    set "PY=py -3"
    set "PYW=pyw -3"
)

%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul || (
    echo Python 3.10 or newer was not found. Install it from https://www.python.org/downloads/
    echo and tick "Add python.exe to PATH".
    pause
    exit /b 1
)
%PY% -c "import tkinter" >nul 2>nul || (
    echo Python was found but Tkinter is missing. Re-run the Python installer and enable "tcl/tk and IDLE".
    pause
    exit /b 1
)
%PY% -c "import cryptography" >nul 2>nul || %PY% -m pip install -r requirements.txt
%PY% -c "import cryptography" >nul 2>nul || (
    echo Could not install the "cryptography" package. Run:  pip install -r requirements.txt
    pause
    exit /b 1
)
rem Optional: drag and drop support. Ignore failures.
%PY% -c "import tkinterdnd2" >nul 2>nul || %PY% -m pip install --quiet tkinterdnd2 >nul 2>nul

start "" %PYW% app.py
