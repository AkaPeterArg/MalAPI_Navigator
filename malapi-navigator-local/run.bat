@echo off
REM Crea el entorno virtual la primera vez y levanta la app.
cd /d "%~dp0"
if not exist .venv (
  echo Creando entorno virtual en .venv...
  py -3 -m venv .venv 2>nul || python -m venv .venv
  if errorlevel 1 (
    echo No se encontro Python 3. Instalalo desde https://www.python.org/downloads/ y marca "Add to PATH".
    pause
    exit /b 1
  )
  .venv\Scripts\python -m pip install --upgrade pip -q
  .venv\Scripts\python -m pip install -r requirements.txt -q
)
.venv\Scripts\python -m streamlit run app.py %*
