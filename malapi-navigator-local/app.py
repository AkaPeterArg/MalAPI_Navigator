"""MalAPI Navigator: edición local con Streamlit.

Python se encarga de leer el catálogo (Excel), analizar binarios con pefile y
guardar las capas en disco. La matriz interactiva es el mismo navegador HTML,
montado como componente bidireccional de Streamlit.

Ejecutar:  streamlit run app.py
"""
from __future__ import annotations

import json
import os
import shutil
import time
import uuid
from functools import partial
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from lib.catalog import CatalogError, catalog_digest, load_catalog
from lib.pe_imports import PEError, analyze_pe

BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("MALAPI_DATA_DIR", BASE / "data")).resolve()
CATALOG_PATH = DATA_DIR / "MalAPI_export.xlsx"
WORKSPACE_PATH = DATA_DIR / "workspace.json"
BACKUP_DIR = DATA_DIR / "backups"
KEEP_BACKUPS = 14
MAX_WORKSPACE_BYTES = 20 * 1024 * 1024

st.set_page_config(page_title="MalAPI Navigator", page_icon="🧭", layout="wide",
                   initial_sidebar_state="expanded")
st.markdown("""<style>
/* La barra superior de Streamlit mide 3.75rem y se vuelve opaca con la barra lateral contraída:
   el contenido arranca debajo para que no tape el encabezado del navegador. */
.block-container{padding-top:3.75rem;padding-bottom:0;padding-left:1rem;padding-right:1rem;max-width:100%}
[data-testid="stSidebar"] .stMetric{padding:0}
</style>""", unsafe_allow_html=True)

navigator = components.declare_component("malapi_navigator", path=str(BASE / "navigator"))


# ---------------------------------------------------------------- persistencia
def read_workspace() -> dict | None:
    if not WORKSPACE_PATH.exists():
        return None
    try:
        return json.loads(WORKSPACE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def valid_workspace(ws) -> bool:
    return (isinstance(ws, dict) and isinstance(ws.get("layers"), dict)
            and isinstance(ws.get("order"), list) and len(ws["order"]) >= 1)


def write_workspace(ws: dict) -> None:
    raw = json.dumps(ws, ensure_ascii=False, indent=1)
    if len(raw.encode()) > MAX_WORKSPACE_BYTES:
        raise ValueError("El espacio de trabajo supera 20 MB; no se guardó.")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if WORKSPACE_PATH.exists():
        shutil.copy2(WORKSPACE_PATH, DATA_DIR / "workspace.prev.json")
        BACKUP_DIR.mkdir(exist_ok=True)
        daily = BACKUP_DIR / f"workspace-{datetime.now():%Y%m%d}.json"
        if not daily.exists():
            shutil.copy2(WORKSPACE_PATH, daily)
            for old in sorted(BACKUP_DIR.glob("workspace-*.json"))[:-KEEP_BACKUPS]:
                old.unlink(missing_ok=True)
    tmp = WORKSPACE_PATH.with_suffix(".tmp")
    tmp.write_text(raw, encoding="utf-8")
    os.replace(tmp, WORKSPACE_PATH)  # escritura atómica


@st.cache_data(show_spinner=False)
def cached_catalog(path: str, mtime: float) -> dict:
    return load_catalog(path)


@st.cache_data(show_spinner="Analizando el PE…", max_entries=16)
def cached_pe(data: bytes, name: str):
    return analyze_pe(data, name)


def rel(p: Path) -> str:
    try:
        return str(p.relative_to(BASE))
    except ValueError:
        return str(p)


# ---------------------------------------------------------------- estado
ss = st.session_state
ss.setdefault("pending", None)
ss.setdefault("save_error", None)
ss.setdefault("last_saved", None)

# ---------------------------------------------------------------- barra lateral
with st.sidebar:
    st.header("MalAPI Navigator")
    st.caption("Edición local. Las capas se guardan en disco y nada sale de esta máquina.")

    st.subheader("Catálogo")
    catalog, catalog_err = None, None
    if CATALOG_PATH.exists():
        try:
            catalog = cached_catalog(str(CATALOG_PATH), CATALOG_PATH.stat().st_mtime)
        except CatalogError as exc:
            catalog_err = str(exc)
    else:
        catalog_err = f"No se encontró {rel(CATALOG_PATH)}."
    if catalog:
        n_assign = sum(len(a[2]) for a in catalog["apis"])
        st.write(f"**{len(catalog['apis'])}** APIs, {n_assign} asignaciones a {len(catalog['cats'])} categorías.")
        st.caption(f"{rel(CATALOG_PATH)}, modificado el "
                   f"{datetime.fromtimestamp(CATALOG_PATH.stat().st_mtime):%d/%m/%Y %H:%M}")
    else:
        st.warning(f"{catalog_err} Se usa el catálogo integrado en el navegador.")
    new_cat = st.file_uploader("Reemplazar por otra exportación (.xlsx)", type=["xlsx"], key="cat_up")
    if new_cat is not None and st.button("Usar este catálogo", key="cat_apply"):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = DATA_DIR / "catalogo_nuevo.tmp.xlsx"
        tmp.write_bytes(new_cat.getvalue())
        try:
            load_catalog(tmp)
        except CatalogError as exc:
            tmp.unlink(missing_ok=True)
            st.error(f"No se reemplazó el catálogo: {exc}")
        else:
            if CATALOG_PATH.exists():
                shutil.copy2(CATALOG_PATH, DATA_DIR / "MalAPI_export.prev.xlsx")
            os.replace(tmp, CATALOG_PATH)
            cached_catalog.clear()
            st.success("Catálogo actualizado.")
            st.rerun()

    st.subheader("Binario")
    st.caption("Se parsea en memoria con pefile: no se guarda en disco ni se ejecuta. "
               "Trabajá igual dentro de tu VM de análisis.")
    up = st.file_uploader("Ejecutable PE (.exe, .dll, .sys…)", key="pe_up")
    if up is not None:
        try:
            rep = cached_pe(up.getvalue(), up.name)
        except PEError as exc:
            st.error(str(exc))
        else:
            c1, c2 = st.columns(2)
            c1.metric("Funciones importadas", len(rep.imports) + len(rep.delay_imports))
            c2.metric("DLL", len(rep.dlls))
            st.caption(f"{rep.machine}{' DLL' if rep.is_dll else ''}, {rep.size:,} bytes, compilado {rep.timestamp_utc}")
            st.code(f"SHA-256 {rep.sha256}\nimphash {rep.imphash or 'n/d'}", language=None)
            for w in rep.warnings:
                st.warning(w)
            if rep.ordinals:
                st.info(f"{len(rep.ordinals)} importaciones por ordinal no se pueden mapear por nombre.")
            with st.expander("Secciones"):
                st.dataframe(pd.DataFrame([{
                    "Sección": s.name, "Entropía": s.entropy, "Tamaño virtual": s.virtual_size,
                    "Tamaño en disco": s.raw_size, "Ejecutable": "sí" if s.executable else ""}
                    for s in rep.sections]), hide_index=True)
            with st.expander("Importaciones"):
                st.dataframe(pd.DataFrame(rep.imports + rep.delay_imports, columns=["DLL", "Función"]),
                             hide_index=True, height=240)
            if st.button("Abrir en el navegador", type="primary", key="send_pe",
                         disabled=not (rep.imports or rep.delay_imports)):
                ss.pending = {"nonce": uuid.uuid4().hex, "text": rep.imports_text(),
                              "name": Path(up.name).stem[:60], "sample": up.name, "sha": rep.sha256}

    st.subheader("Espacio de trabajo")
    ws_disk = read_workspace()
    if ws_disk and valid_workspace(ws_disk):
        n_layers = len(ws_disk["order"])
        st.write(f"**{n_layers}** capa{'s' if n_layers != 1 else ''} guardada{'s' if n_layers != 1 else ''} en `{rel(WORKSPACE_PATH)}`.")
        st.caption(f"Último guardado: {datetime.fromtimestamp(WORKSPACE_PATH.stat().st_mtime):%d/%m/%Y %H:%M:%S}. "
                   f"Copias diarias en `{rel(BACKUP_DIR)}` (últimos {KEEP_BACKUPS} días).")
        st.download_button("Descargar respaldo (JSON)", WORKSPACE_PATH.read_bytes(),
                           file_name=f"malapi-workspace-{datetime.now():%Y%m%d-%H%M}.json",
                           mime="application/json", key="dl_ws")
    else:
        st.write("Todavía no hay capas guardadas.")
    if ss.save_error:
        st.error(ss.save_error)

    st.subheader("Vista")
    auto_h = st.toggle("Ajustar al alto de la ventana", value=True, key="auto_h",
                       help="El navegador ocupa el alto disponible y se reajusta al cambiar el tamaño de la ventana.")
    height = 0 if auto_h else st.slider("Alto del navegador (px)", 480, 1800, 900, 20, key="height")

# ---------------------------------------------------------------- navegador
def on_navigator_change(key: str) -> None:
    """Corre antes del siguiente rerun: guarda en disco y confirma importaciones."""
    value = ss.get(key)
    if not isinstance(value, dict):
        return
    rev = value.get("rev")
    if rev is not None and rev != ss.get(f"rev-{key}"):
        ss[f"rev-{key}"] = rev
        ws = value.get("workspace")
        if valid_workspace(ws):
            try:
                write_workspace(ws)
                ss.save_error = None
                ss.last_saved = time.time()
            except (OSError, ValueError) as exc:
                ss.save_error = f"No se pudo guardar en disco: {exc}"
    if ss.pending and value.get("ack") == ss.pending.get("nonce"):
        ss.pending = None


cat_key = catalog_digest(catalog) if catalog else "integrado"
comp_key = f"nav-{cat_key}"
navigator(
    catalog=catalog,
    workspace=ws_disk if (ws_disk and valid_workspace(ws_disk)) else None,
    pending=ss.pending,
    height=height,
    save_label=rel(WORKSPACE_PATH),
    key=comp_key,
    default=None,
    on_change=partial(on_navigator_change, comp_key),
)
