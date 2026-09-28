"""Genera capas del navegador a partir de una carpeta de binarios, sin abrir la interfaz.

Uso:  python capas_por_lote.py CARPETA_DE_MUESTRAS salida.json
Después, en el navegador: + Nueva capa -> Importar archivo JSON -> salida.json
"""
import json
import re
import sys
from pathlib import Path

from lib.catalog import load_catalog
from lib.pe_imports import PEError, analyze_pe

WEIGHTS = {"Enumeration": 2, "Injection": 5, "Evasion": 4, "Spying": 4,
           "Internet": 3, "Anti-Debugging": 4, "Ransomware": 5, "Helper": 1}


def base(name: str) -> str:
    """Misma normalización que el navegador: A/W, _A/_W, Zw->Nt, _Func@N, __imp_."""
    s = re.sub(r"^__imp_?", "", name, flags=re.I)
    s = re.sub(r"@\d+$", "", re.sub(r"^_+", "", s))
    s = re.sub(r"_(A|W)$", "", s)
    if re.search(r"[a-z0-9](A|W)$", s):
        s = s[:-1]
    s = s.lower()
    return "nt" + s[2:] if s.startswith("zw") else s


def main(folder: str, out: str) -> None:
    cat = load_catalog(Path(__file__).parent / "data" / "MalAPI_export.xlsx")
    cats = cat["cats"]
    by_key, by_base = {}, {}
    for api in cat["apis"]:
        by_key[api[0].lower()] = api
        by_base.setdefault(base(api[0]), api)

    layers = []
    for f in sorted(Path(folder).iterdir()):
        if not f.is_file():
            continue
        try:
            rep = analyze_pe(f.read_bytes(), f.name)
        except PEError as exc:
            print(f"  omitido {f.name}: {exc}")
            continue
        entries, unmatched = {}, set()
        for _dll, fn in rep.imports + rep.delay_imports:
            api = by_key.get(fn.lower()) or by_base.get(base(fn))
            if not api:
                unmatched.add(fn)
                continue
            e = entries.setdefault(api[0], {"api": api[0], "score": max(WEIGHTS[cats[i]] for i in api[2]), "as": set()})
            if fn != api[0]:
                e["as"].add(fn)
        for e in entries.values():
            if e["as"]:
                e["comment"] = "Importada como " + ", ".join(sorted(e["as"]))
            del e["as"]
        layers.append({"name": f.stem[:80], "sample": {"name": f.name, "hash": rep.sha256},
                       "description": f"imphash {rep.imphash}. " + " ".join(rep.warnings),
                       "entries": list(entries.values()), "unmatched": sorted(unmatched)})
        print(f"  {f.name}: {len(entries)} APIs del catálogo, {len(unmatched)} fuera")
    Path(out).write_text(json.dumps({"format": "malapi-workspace", "version": 1, "layers": layers},
                                    ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{len(layers)} capas en {out}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
