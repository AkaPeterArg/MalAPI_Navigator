"""Lectura del catálogo MalAPI exportado a Excel.

Convierte la hoja ``Catalogo_APIs`` al formato compacto que consume el navegador:
``{"cats": [...], "apis": [[name, dll, [idx_cat...], desc, doc, created, credit], ...]}``
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

import pandas as pd

CATEGORIES = ["Enumeration", "Injection", "Evasion", "Spying", "Internet",
              "Anti-Debugging", "Ransomware", "Helper"]
SHEET = "Catalogo_APIs"
REQUIRED = ["API", "Librería (DLL)", "Descripción"]
MS_PREFIX = "https://docs.microsoft.com/en-us/"
PLACEHOLDER_PREFIX = "(Detalle no disponible"


class CatalogError(ValueError):
    """El archivo no tiene la estructura esperada de la exportación de MalAPI."""


def _text(v) -> str:
    return v.strip() if isinstance(v, str) else ""


def load_catalog(path: str | Path) -> dict:
    path = Path(path)
    if not path.exists():
        raise CatalogError(f"No existe el archivo {path}")
    try:
        sheets = pd.read_excel(path, sheet_name=None)
    except Exception as exc:  # archivo dañado o no es Excel
        raise CatalogError(f"No se pudo leer {path.name} como Excel: {exc}") from exc
    if SHEET not in sheets:
        raise CatalogError(f"Falta la hoja '{SHEET}'. Hojas encontradas: {', '.join(sheets)}")
    df = sheets[SHEET]
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise CatalogError(f"Faltan columnas en '{SHEET}': {', '.join(missing)}")

    has_flags = all(c in df.columns for c in CATEGORIES)
    if not has_flags and "Categorías (tabla principal)" not in df.columns:
        raise CatalogError("No hay columnas de categoría (ni las 8 marcas ni 'Categorías (tabla principal)')")

    df = df[df["API"].map(lambda v: isinstance(v, str) and v.strip() != "")]
    if df.empty:
        raise CatalogError("La hoja no tiene APIs")
    dups = df["API"][df["API"].duplicated()].tolist()
    if dups:
        raise CatalogError(f"APIs duplicadas: {', '.join(dups[:10])}")

    # misma DLL escrita con distintas mayúsculas -> forma más frecuente
    counts = Counter(_text(v) for v in df["Librería (DLL)"] if _text(v))
    canon: dict[str, str] = {}
    for name, _ in counts.most_common():
        canon.setdefault(name.lower(), name)

    apis = []
    for _, r in df.iterrows():
        if has_flags:
            cats = [i for i, c in enumerate(CATEGORIES) if _text(r[c])]
        else:
            names = [x.strip() for x in _text(r["Categorías (tabla principal)"]).split(",")]
            cats = [CATEGORIES.index(n) for n in names if n in CATEGORIES]
        dll = _text(r["Librería (DLL)"])
        desc = _text(r["Descripción"])
        if desc.startswith(PLACEHOLDER_PREFIX):
            desc = ""
        doc = _text(r.get("Documentación"))
        if doc.startswith(MS_PREFIX):
            doc = doc[len(MS_PREFIX):]
        created = r.get("Creado")
        created = str(created)[:10] if pd.notna(created) else ""
        apis.append([r["API"].strip(), canon.get(dll.lower(), dll), cats, desc, doc,
                     created, _text(r.get("Créditos"))])
    return {"cats": list(CATEGORIES), "apis": apis}


def catalog_digest(catalog: dict) -> str:
    raw = json.dumps(catalog, ensure_ascii=False, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()[:12]
