"""End-to-end: levanta `streamlit run app.py` y lo maneja con Playwright.

    pytest tests/test_streamlit_e2e.py
Requiere: pip install -r requirements-dev.txt && playwright install chromium
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
PE_FIXTURE = ROOT / "tests" / "fixtures" / "distlib_t64.exe"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    data = tmp_path_factory.mktemp("data")
    shutil.copy(ROOT / "data" / "MalAPI_export.xlsx", data / "MalAPI_export.xlsx")
    port = free_port()
    env = dict(os.environ, MALAPI_DATA_DIR=str(data))
    proc = subprocess.Popen([sys.executable, "-m", "streamlit", "run", str(ROOT / "app.py"),
                             "--server.port", str(port), "--server.headless", "true"],
                            cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    url = f"http://localhost:{port}"
    for _ in range(80):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.25)
    else:
        proc.kill()
        pytest.fail("Streamlit no arrancó")
    yield url, data
    proc.terminate()
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


def nav_frame(page):
    page.wait_for_selector("iframe[title*='malapi_navigator']", timeout=30000)
    for _ in range(100):
        for f in page.frames:
            if "malapi_navigator" in f.url:
                try:
                    if f.evaluate("typeof store!=='undefined' && store.mode==='host' && document.querySelectorAll('.cell').length>0"):
                        return f
                except Exception:
                    pass
        page.wait_for_timeout(150)
    raise AssertionError("El componente no pasó a modo host")


def read_ws(data):
    p = data / "workspace.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def wait_ws(data, pred, timeout=15):
    t0 = time.time()
    while time.time() - t0 < timeout:
        ws = read_ws(data)
        if ws and pred(ws):
            return ws
        time.sleep(0.2)
    raise AssertionError(f"workspace.json no cumplió la condición: {read_ws(data)}")


def test_flujo_completo(server, browser):
    url, data = server
    page = browser.new_page(viewport={"width": 1600, "height": 1000}, accept_downloads=True)
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(url)
    f = nav_frame(page)

    # 1. arranque: catálogo desde Python, modo host, guardado inicial en disco
    assert f.evaluate("API.length") == 370
    assert f.locator(".cell").count() == 428
    f.wait_for_function("document.getElementById('saveState').textContent.startsWith('Guardado en disco')", timeout=10000)
    ws = wait_ws(data, lambda w: len(w["order"]) == 1)
    assert ws["layers"][ws["order"][0]]["name"] == "Capa 1"

    # 2. por defecto el navegador ocupa el alto disponible de la ventana (1000 px)
    top, bottom, _ = page.evaluate(IFRAME_BOX)
    assert 960 <= bottom <= 1000, (top, bottom)

    # 3. binario -> pefile -> diálogo de importación precargado
    page.locator("[data-testid='stFileUploaderDropzoneInput']").nth(1).set_input_files(str(PE_FIXTURE))
    expect(page.get_by_text("Funciones importadas")).to_be_visible(timeout=20000)
    expect(page.get_by_text("c51d659b4b1142d4af3795d09f1d63f7")).to_be_visible()
    page.get_by_role("button", name="Abrir en el navegador").click()
    f.wait_for_function("document.getElementById('dlg').open", timeout=15000)
    assert f.input_value("#imName") == "distlib_t64"
    assert f.input_value("#imSample") == "distlib_t64.exe"
    assert len(f.input_value("#imHash")) == 64
    assert "KERNEL32.dll!CreateProcessW" in f.input_value("#imText")
    prev = f.inner_text("#imPrev")
    assert "Coinciden" in prev, prev
    f.click("#dlg .dlg-f button.primary")

    # 4. la capa llega a disco
    ws = wait_ws(data, lambda w: len(w["order"]) == 2)
    layer = ws["layers"][ws["order"][1]]
    assert layer["name"] == "distlib_t64" and layer["sample"]["name"] == "distlib_t64.exe"
    assert "CreateProcessA" in layer["entries"]
    assert "Importada como CreateProcessW" in layer["entries"]["CreateProcessA"]["m"]
    n_entries = len(layer["entries"])
    assert n_entries > 10

    # 5. el diálogo no se reabre en reruns posteriores (nonce confirmado)
    page.get_by_text("Ajustar al alto de la ventana").click()   # fuerza reruns de Streamlit
    page.wait_for_timeout(1200)
    page.get_by_text("Ajustar al alto de la ventana").click()
    page.wait_for_timeout(1200)
    f = nav_frame(page)
    assert not f.evaluate("document.getElementById('dlg').open")

    # 6. editar en la matriz -> disco
    f.click(".cell[data-api=Sleep] >> nth=0")
    f.press("body", "7")
    wait_ws(data, lambda w: w["layers"][w["order"][1]]["entries"].get("Sleep", {}).get("s") == 7)

    # 7. la barra lateral muestra el estado recién guardado
    expect(page.get_by_text("2 capas guardadas")).to_be_visible(timeout=10000)
    assert (data / "workspace.prev.json").exists()
    assert list((data / "backups").glob("workspace-*.json"))

    # 8. descarga desde dentro del iframe
    f.click("[data-ptab=layer]")
    with page.expect_download() as d:
        f.click("button[data-act=exportCsv]")
    dl = d.value
    assert dl.suggested_filename == "malapi-capa-distlib_t64.csv"
    assert "CreateProcessA" in open(dl.path(), encoding="utf-8").read()

    # 9. recargar = nueva sesión: todo sale del disco
    page.reload()
    f = nav_frame(page)
    assert f.evaluate("S.order.length") == 2
    assert f.evaluate("S.layers[S.order[1]].entries.Sleep.s") == 7
    assert f.evaluate("Object.keys(S.layers[S.order[1]].entries).length") == n_entries + 1 or \
        f.evaluate("Object.keys(S.layers[S.order[1]].entries).length") == n_entries
    assert not f.evaluate("document.getElementById('dlg').open")

    # 10. superposición y limpiar también persisten
    f.evaluate("S.activeId=S.order[1]; renderAll()")
    f.click("#ibClear")
    f.click("#dlg .choice button[data-c=layer]")
    wait_ws(data, lambda w: len(w["layers"][w["order"][1]]["entries"]) == 0)
    f.click("#toast button")
    wait_ws(data, lambda w: len(w["layers"][w["order"][1]]["entries"]) > 10)

    assert not errors, errors
    page.close()


def test_catalogo_invalido_no_reemplaza(server, browser, tmp_path):
    url, data = server
    bad = tmp_path / "malo.xlsx"
    bad.write_text("no soy excel")
    before = (data / "MalAPI_export.xlsx").read_bytes()
    page = browser.new_page(viewport={"width": 1600, "height": 1000})
    page.goto(url)
    nav_frame(page)
    page.locator("[data-testid='stFileUploaderDropzoneInput']").nth(0).set_input_files(str(bad))
    page.get_by_role("button", name="Usar este catálogo").click()
    expect(page.get_by_text("No se reemplazó el catálogo")).to_be_visible(timeout=10000)
    assert (data / "MalAPI_export.xlsx").read_bytes() == before
    page.close()


def test_binario_no_pe(server, browser, tmp_path):
    url, _ = server
    f = tmp_path / "nota.txt"
    f.write_text("esto no es un ejecutable")
    page = browser.new_page(viewport={"width": 1600, "height": 1000})
    page.goto(url)
    nav_frame(page)
    page.locator("[data-testid='stFileUploaderDropzoneInput']").nth(1).set_input_files(str(f))
    expect(page.get_by_text("no es un ejecutable PE")).to_be_visible(timeout=10000)
    page.close()


HEADER_CHECK = """(()=>{const q=s=>document.querySelector(s), R=e=>e.getBoundingClientRect(), vw=innerWidth;
  const vis=e=>{const r=R(e);return r.width>0&&r.left>=-1&&r.right<=vw+1};
  return {tabsHidden:q('#tabs').scrollWidth>q('#tabs').clientWidth+1,
    namesCut:[...document.querySelectorAll('.tab .tname')].filter(t=>t.scrollWidth>t.clientWidth+1).length,
    buttons:[...document.querySelectorAll('.hctrl .ib')].every(vis), save:vis(q('#saveState')),
    overflow:document.documentElement.scrollWidth>vw+1}})()"""
IFRAME_BOX = "(()=>{const r=document.querySelector(\"iframe[title*='malapi_navigator']\").getBoundingClientRect();return [r.top,r.bottom,r.height]})()"


def test_encabezado_y_alto_en_resoluciones_comunes(server, browser):
    """Regresión: en 1366x768 las pestañas de capas quedaban en 0 px y había doble scroll."""
    url, data = server
    page = browser.new_page(viewport={"width": 1920, "height": 1080})
    page.goto(url)
    f = nav_frame(page)
    f.evaluate("""(()=>{S.layers={}; S.order=[];
      for(const n of ['Capa 1','Dropper campaña Q3 variante B','distlib_t64 (copia)','Superposición ABC'])
        addLayer(newLayer(n),S.order.length===0); renderAll();})()""")
    for w, h in [(1280, 720), (1366, 768), (1440, 900), (1536, 730), (1920, 1080)]:
        page.set_viewport_size({"width": w, "height": h})
        page.wait_for_timeout(700)
        r = f.evaluate(HEADER_CHECK)
        assert not r["tabsHidden"] and r["namesCut"] == 0, (w, h, r)
        assert r["buttons"] and r["save"] and not r["overflow"], (w, h, r)
        top, bottom, _ = page.evaluate(IFRAME_BOX)
        assert bottom <= h and bottom >= h - 40, f"{w}x{h}: el navegador no se ajusta al alto ({top:.0f}-{bottom:.0f})"
        assert not page.evaluate("(()=>{const m=document.querySelector('[data-testid=stMain]');return m.scrollHeight>m.clientHeight+2})()"), \
            f"{w}x{h}: doble scroll"
    # alto fijo manual
    page.get_by_text("Ajustar al alto de la ventana").click()
    page.wait_for_timeout(1500)
    assert abs(page.evaluate(IFRAME_BOX)[2] - 900) < 2
    page.get_by_text("Ajustar al alto de la ventana").click()
    page.wait_for_timeout(1500)
    assert page.evaluate(IFRAME_BOX)[1] <= 1080
    page.close()


def test_barra_superior_de_streamlit_no_tapa_el_navegador(server, browser):
    """Regresión: con la barra lateral contraída, la barra superior de Streamlit (opaca, 60 px) tapaba el encabezado."""
    url, _ = server
    page = browser.new_page(viewport={"width": 1880, "height": 1000})
    page.goto(url)
    nav_frame(page)
    js = """(()=>{const i=document.querySelector("iframe[title*='malapi_navigator']").getBoundingClientRect();
      const h=document.querySelector('[data-testid=stHeader]').getBoundingClientRect();
      const hit=document.elementFromPoint(i.x+400, i.y+3);
      return {iframeTop:i.top, headerBottom:h.bottom, hit:hit.tagName, bottom:i.bottom}})()"""
    for estado in ("expandida", "contraída"):
        if estado == "contraída":
            btn = page.locator("[data-testid='stSidebarCollapseButton'] button, [data-testid='stSidebarHeader'] button").first
            btn.hover(); btn.click(); page.wait_for_timeout(1200)
        r = page.evaluate(js)
        assert r["iframeTop"] >= r["headerBottom"], (estado, r)
        assert r["hit"] == "IFRAME", (estado, r)       # el clic en el borde superior llega al navegador
        assert r["bottom"] <= 1000, (estado, r)         # y sigue entrando en la ventana
        f = nav_frame(page)
        assert f.evaluate("document.querySelector('.hctrl').getBoundingClientRect().top") >= 0
    page.close()


def test_exportar_imagen_y_excel_desde_streamlit(server, browser):
    """El componente vive en un iframe con sandbox: PNG (canvas) y XLSX (Blob) tienen que descargarse igual."""
    import struct, zipfile, io
    url, _ = server
    page = browser.new_page(viewport={"width": 1600, "height": 1000}, accept_downloads=True)
    page.goto(url)
    f = nav_frame(page)
    f.evaluate("(()=>{S.layers[S.order[0]].entries={VirtualAllocEx:{s:5},Sleep:{s:3,c:'#3f8fbf'}}; S.layers[S.order[0]].legend=[{color:'#3f8fbf',label:'Visto'}]; renderAll();})()")
    f.click("#ibExport")
    f.click("#expMenu [data-exp=svg]")
    f.wait_for_selector("#rvPrev svg")
    with page.expect_download() as d:
        f.click("#dlg .dlg-f button:has-text('Descargar PNG')")
    data = open(d.value.path(), "rb").read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n" and struct.unpack(">II", data[16:24]) == (2112, 1632)
    with page.expect_download() as d:
        f.click("#dlg .dlg-f button:has-text('Descargar SVG')")
    assert d.value.suggested_filename.endswith(".svg")
    f.click("#dlg [data-close]")
    f.click("#ibExport")
    with page.expect_download() as d:
        f.click("#expMenu [data-exp=xlsx1]")
    z = zipfile.ZipFile(io.BytesIO(open(d.value.path(), "rb").read()))
    assert z.testzip() is None and "xl/workbook.xml" in z.namelist()
    page.close()
