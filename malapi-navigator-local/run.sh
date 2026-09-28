#!/usr/bin/env bash
# Crea el entorno virtual la primera vez y levanta la app.
set -euo pipefail
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
if [ ! -d .venv ]; then
  echo "Creando entorno virtual en .venv..."
  "$PY" -m venv .venv
  .venv/bin/python -m pip install --upgrade pip -q
  .venv/bin/python -m pip install -r requirements.txt -q
fi
exec .venv/bin/python -m streamlit run app.py "$@"
