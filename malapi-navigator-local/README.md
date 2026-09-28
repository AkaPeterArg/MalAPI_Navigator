# MalAPI Navigator: edición local

Matriz tipo ATT&CK Navigator sobre el catálogo de APIs de Windows de MalAPI.io. Tiene capas con score, color y comentario, superposición de capas por expresión, perfil de capacidades y exportación a JSON/CSV. Corre completo en tu máquina, sin depender de claude.ai.

Hay dos formas de usarla, con la misma interfaz.

## Opción A: archivo HTML suelto (sin instalar nada)

Abrí `malapi-navigator.html` con doble clic en Chrome, Edge o Firefox.

- El catálogo MalAPI ya viene integrado en el archivo.
- Las capas se guardan en el almacenamiento local de ese navegador. Si borrás los datos de navegación, se pierden; exportá las capas en JSON como respaldo.
- Pegás las importaciones del binario a mano (salida de pefile, PEStudio, `rabin2 -i`, `dumpbin /imports`).
- Funciona sin conexión. Si no hay internet, usa las fuentes del sistema en lugar de las de Google Fonts.

## Opción B: aplicación con Streamlit (recomendada para uso diario)

Suma sobre la opción A:

- **Análisis del binario en Python.** Subís el `.exe`/`.dll` y `pefile` extrae las importaciones, hashes, imphash, secciones y alertas de empaquetado. Con un botón se abren en el navegador, listas para importar.
- **Guardado en disco.** Las capas se guardan en `data/workspace.json`, con la versión anterior en `workspace.prev.json` y copias diarias en `data/backups/` (últimos 14 días).
- **Catálogo actualizable.** Si exportás de nuevo MalAPI a Excel, lo reemplazás desde la barra lateral y se valida antes de usarlo.

### Instalación (una sola vez)

Requiere Python 3.10 o superior.

Windows:
```bat
run.bat
```

Linux / macOS:
```bash
./run.sh
```

Los scripts crean un entorno virtual en `.venv`, instalan las dependencias y abren la app en http://localhost:8501.

Manual, si preferís:
```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

### Uso

1. En la barra lateral, **Binario**: subí el ejecutable. Vas a ver las funciones importadas, el SHA-256, el imphash y las alertas (tabla de importaciones corta, secciones de alta entropía, nombres de empaquetadores, timestamp falseado).
2. Tocá **Abrir en el navegador**. Se abre el diálogo de importación con el nombre, la muestra y el hash completos. Elegí el criterio de score y confirmá.
3. Trabajá en la matriz igual que en la versión web. El estado arriba a la derecha dice "Guardado en disco" cuando los cambios ya están en `data/workspace.json`.
4. **Alto del navegador** (barra lateral) ajusta la altura de la matriz. Podés contraer la barra lateral de Streamlit para ganar ancho.

### Seguridad

- El binario se parsea en memoria con `pefile`: no se escribe a disco ni se ejecuta. Aun así, abrí muestras reales solo dentro de tu VM de análisis.
- La app escucha solo en `localhost` (ver `.streamlit/config.toml`). Para compartirla en la red del laboratorio cambiá `address = "0.0.0.0"`. Tené en cuenta que no tiene autenticación y que todos los que se conecten comparten el mismo `workspace.json`: gana el último que guarda.
- La telemetría de Streamlit está desactivada (`gatherUsageStats = false`).

### Interpretación

Las importaciones muestran **capacidades presentes**, no comportamiento. El archivo de prueba `tests/fixtures/distlib_t64.exe` es el lanzador legítimo que usa pip en Windows, y aun así marca 26 APIs del catálogo y completa dos combinaciones indicativas. Usá la matriz para priorizar qué mirar en CAPA, Ghidra o un sandbox, no como veredicto.

## Exportar (como en ATT&CK Navigator)

El botón **Exportar** del encabezado reúne todas las salidas en un solo menú, como Navigator desde la versión 4.9:

- **Imagen de la matriz (SVG o PNG).** Abre una vista con previsualización en vivo y las opciones del render de Navigator:
  - unidades in, cm o px;
  - ancho, alto y alto del encabezado, con presets (Carta, A4, A3, Tabloide, diapositiva 16:9) y botón para rotar;
  - fuente serif, sans-serif o monospace, con tamaño de texto automático;
  - texto de celda: nombre, nombre y score, o ninguno (vista mini);
  - APIs a mostrar: según la vista, solo anotadas o todas;
  - encabezado con Capa, Muestra, Filtros y Leyenda, cada uno ocultable;
  - leyenda acoplada o flotante (X, Y, ancho, alto);
  - tema claro u oscuro, color de borde de celdas y fondo de la fila de categorías.

  El PNG sale a 1×, 2× o 3×.
- **Excel (.xlsx):** la capa actual o todas las capas. Cada capa genera una hoja con la matriz tal como se ve (orden, filtros y columnas ocultas) y las celdas coloreadas, más una hoja de detalle con DLL, categorías, peso, score, color y comentario.
- **JSON y CSV.** La opción **Solo anotaciones de APIs visibles** omite lo que está oculto por filtros, igual que en Navigator.

La **Leyenda** de la pestaña Capa asigna etiquetas a los colores manuales. Se guarda en la capa, aparece en la imagen exportada y se intercambia con Navigator como `legendItems`.

## Capas por lote (sin interfaz)

Para procesar una carpeta entera de muestras:

```bash
python capas_por_lote.py C:\muestras capas.json
```

Genera una capa por binario, con los mismos scores y comentarios que la importación desde la interfaz. Omite los archivos que no son PE. Después, en el navegador: **+ Nueva capa** → **Importar archivo JSON** → `capas.json`.

## Estructura

```
app.py                  Aplicación Streamlit
capas_por_lote.py       Genera capas desde una carpeta de binarios
lib/catalog.py          Lectura y validación del Excel de MalAPI
lib/pe_imports.py       Análisis estático del PE con pefile
navigator/index.html    Matriz interactiva (componente de Streamlit)
malapi-navigator.html   La misma matriz, para usar suelta (opción A)
data/                   Catálogo, espacio de trabajo y respaldos
tests/                  Suites de tests
```

`navigator/index.html` y `malapi-navigator.html` son el mismo archivo. Detecta dónde corre: dentro de Streamlit guarda en disco a través de Python; suelto, guarda en el navegador.

## Tests

```bash
pip install -r requirements-dev.txt
playwright install chromium
pytest tests/test_python.py            # catálogo y pefile
pytest tests/test_streamlit_e2e.py     # levanta Streamlit y recorre el flujo completo
python tests/test_navigator.py         # matriz, capas, superposición, exportación, vista
```

## Migrar capas desde la versión de claude.ai

En la versión web, pestaña **Capa** → **Todas las capas** (JSON). En la local, **+ Nueva capa** → **Importar archivo JSON**.
