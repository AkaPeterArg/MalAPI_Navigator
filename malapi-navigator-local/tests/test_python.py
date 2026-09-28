"""Tests unitarios de lib/catalog.py y lib/pe_imports.py.   pytest tests/test_python.py"""
import json
import shutil
import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib.catalog import CATEGORIES, CatalogError, catalog_digest, load_catalog  # noqa: E402
from lib.pe_imports import PEError, analyze_pe  # noqa: E402

XLSX = ROOT / "data" / "MalAPI_export.xlsx"
PE_FIXTURE = ROOT / "tests" / "fixtures" / "distlib_t64.exe"


# ------------------------------------------------------------------ catálogo
@pytest.fixture(scope="module")
def cat():
    return load_catalog(XLSX)


def test_catalogo_conteos(cat):
    assert cat["cats"] == CATEGORIES
    assert len(cat["apis"]) == 370
    assert sum(len(a[2]) for a in cat["apis"]) == 428
    assert sum(1 for a in cat["apis"] if len(a[2]) > 1) == 53


def test_catalogo_conteo_por_categoria_igual_a_resumen(cat):
    per = [sum(1 for a in cat["apis"] if i in a[2]) for i in range(8)]
    assert per == [73, 91, 38, 29, 41, 24, 21, 111]


def test_catalogo_dll_normalizadas(cat):
    dlls = {a[1] for a in cat["apis"] if a[1]}
    assert len(dlls) == len({d.lower() for d in dlls})
    assert "ntdll.dll" not in dlls and "Ntdll.dll" in dlls


def test_catalogo_readfile_sin_texto_de_relleno(cat):
    rf = next(a for a in cat["apis"] if a[0] == "ReadFile")
    assert rf[3] == "" and rf[1] == ""


def test_catalogo_igual_al_integrado_en_el_html(cat):
    html = (ROOT / "navigator" / "index.html").read_text(encoding="utf-8")
    start = html.index("let DATA = ") + len("let DATA = ")
    end = html.index(";\nlet CATS", start)
    assert json.loads(html[start:end]) == cat


def test_catalogo_digest_estable(cat):
    assert catalog_digest(cat) == catalog_digest(json.loads(json.dumps(cat)))
    assert len(catalog_digest(cat)) == 12


def test_catalogo_archivo_inexistente(tmp_path):
    with pytest.raises(CatalogError, match="No existe"):
        load_catalog(tmp_path / "no.xlsx")


def test_catalogo_no_es_excel(tmp_path):
    f = tmp_path / "x.xlsx"
    f.write_text("hola")
    with pytest.raises(CatalogError, match="No se pudo leer"):
        load_catalog(f)


def test_catalogo_sin_hoja(tmp_path):
    f = tmp_path / "x.xlsx"
    pd.DataFrame({"a": [1]}).to_excel(f, sheet_name="Otra", index=False)
    with pytest.raises(CatalogError, match="Falta la hoja"):
        load_catalog(f)


def test_catalogo_sin_columnas(tmp_path):
    f = tmp_path / "x.xlsx"
    pd.DataFrame({"API": ["X"]}).to_excel(f, sheet_name="Catalogo_APIs", index=False)
    with pytest.raises(CatalogError, match="Faltan columnas"):
        load_catalog(f)


def test_catalogo_duplicados(tmp_path):
    f = tmp_path / "x.xlsx"
    pd.DataFrame({"API": ["A", "A"], "Librería (DLL)": ["k", "k"], "Descripción": ["", ""],
                  "Categorías (tabla principal)": ["Injection", "Injection"]}).to_excel(f, sheet_name="Catalogo_APIs", index=False)
    with pytest.raises(CatalogError, match="duplicadas"):
        load_catalog(f)


def test_catalogo_formato_alternativo_por_texto(tmp_path):
    f = tmp_path / "x.xlsx"
    pd.DataFrame({"API": ["Foo", "Bar"], "Librería (DLL)": ["kernel32.dll", "Kernel32.dll"], "Descripción": ["d", "e"],
                  "Categorías (tabla principal)": ["Injection, Evasion", "Helper"]}).to_excel(f, sheet_name="Catalogo_APIs", index=False)
    c = load_catalog(f)
    assert c["apis"][0][2] == [1, 2] and c["apis"][1][2] == [7]
    assert c["apis"][0][1] == c["apis"][1][1]


# ------------------------------------------------------------------ PE
@pytest.fixture(scope="module")
def rep():
    return analyze_pe(PE_FIXTURE.read_bytes(), PE_FIXTURE.name)


def test_pe_hashes_y_cabecera(rep):
    import hashlib
    data = PE_FIXTURE.read_bytes()
    assert rep.sha256 == hashlib.sha256(data).hexdigest()
    assert rep.machine == "x64" and not rep.is_dll
    assert rep.imphash == "c51d659b4b1142d4af3795d09f1d63f7"


def test_pe_importaciones(rep):
    assert rep.dlls == ["KERNEL32.dll", "SHLWAPI.dll"]
    assert len(rep.imports) == 86
    assert ("KERNEL32.dll", "CreateProcessW") in rep.imports


def test_pe_texto_para_el_navegador(rep):
    lines = rep.imports_text().splitlines()
    assert len(lines) == 86 and all("!" in l for l in lines)
    assert "KERNEL32.dll!CreateProcessW" in lines


def test_pe_secciones(rep):
    names = [s.name for s in rep.sections]
    assert ".text" in names
    assert any(s.executable for s in rep.sections)


def test_pe_benigno_sin_alertas_de_empaquetado(rep):
    assert not any("empaquet" in w for w in rep.warnings), rep.warnings


def test_pe_rechaza_no_pe():
    with pytest.raises(PEError, match="MZ"):
        analyze_pe(b"\x7fELF" + b"\x00" * 100)
    with pytest.raises(PEError):
        analyze_pe(b"")


def test_pe_rechaza_mz_truncado():
    with pytest.raises(PEError, match="pefile"):
        analyze_pe(b"MZ" + b"\x00" * 10)


def test_pe_alertas_heuristicas(tmp_path):
    """Modifica una copia: timestamp 0 y nombre de sección UPX0 → deben aparecer las alertas."""
    import pefile
    pe = pefile.PE(data=PE_FIXTURE.read_bytes())
    pe.FILE_HEADER.TimeDateStamp = 0
    pe.sections[0].Name = b"UPX0\x00\x00\x00\x00"
    data = pe.write()
    r = analyze_pe(bytes(data), "mod.exe")
    assert any("TimeDateStamp en 0" in w for w in r.warnings)
    assert any("UPX0" in w for w in r.warnings)


# ------------------------------------------------------------------ lote
def test_capas_por_lote(tmp_path):
    import capas_por_lote
    muestras = tmp_path / "m"
    muestras.mkdir()
    shutil.copy(PE_FIXTURE, muestras / "a.exe")
    (muestras / "nota.txt").write_text("no es PE")
    out = tmp_path / "capas.json"
    capas_por_lote.main(str(muestras), str(out))
    ws = json.loads(out.read_text(encoding="utf-8"))
    assert ws["format"] == "malapi-workspace" and len(ws["layers"]) == 1
    layer = ws["layers"][0]
    assert layer["sample"]["name"] == "a.exe" and len(layer["sample"]["hash"]) == 64
    assert len(layer["entries"]) == 26
    cp = next(e for e in layer["entries"] if e["api"] == "CreateProcessA")
    assert cp["score"] == 5 and cp["comment"] == "Importada como CreateProcessW"


def test_normalizacion_igual_al_navegador():
    from capas_por_lote import base
    assert base("VirtualAllocExW") == base("VirtualAllocEx")
    assert base("ZwUnmapViewOfSection") == base("NtUnmapViewOfSection")
    assert base("_Sleep@4") == "sleep" and base("__imp_VirtualProtect") == "virtualprotect"
    assert base("DnsQuery_W") == base("DnsQuery_A")
