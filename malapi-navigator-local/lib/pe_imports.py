"""Análisis estático mínimo de un PE: hashes, secciones e importaciones.

Solo parsea bytes con pefile; nunca escribe la muestra a disco ni la ejecuta.
"""
from __future__ import annotations

import datetime as dt
import hashlib
from dataclasses import dataclass, field

import pefile

PACKER_SECTIONS = {"upx0", "upx1", "upx2", ".aspack", ".adata", ".mpress1", ".mpress2", ".themida",
                   ".vmp0", ".vmp1", ".petite", ".nsp0", ".nsp1", ".packed", ".enigma1", ".enigma2"}
DYNAMIC_RESOLUTION = {"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
                      "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress", "getmodulehandlea", "getmodulehandlew"}
MACHINES = {0x14c: "x86", 0x8664: "x64", 0xaa64: "ARM64", 0x1c4: "ARMv7"}
DELPHI_TS = 0x2A425E19


class PEError(ValueError):
    """Los bytes no son un PE que pefile pueda parsear."""


@dataclass
class Section:
    name: str
    entropy: float
    virtual_size: int
    raw_size: int
    executable: bool


@dataclass
class PEReport:
    filename: str
    size: int
    md5: str
    sha1: str
    sha256: str
    imphash: str
    machine: str
    is_dll: bool
    timestamp: int
    timestamp_utc: str
    sections: list[Section] = field(default_factory=list)
    imports: list[tuple[str, str]] = field(default_factory=list)       # (dll, función)
    ordinals: list[tuple[str, int]] = field(default_factory=list)      # (dll, ordinal)
    delay_imports: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def dlls(self) -> list[str]:
        return sorted({d for d, _ in self.imports + self.delay_imports} | {d for d, _ in self.ordinals})

    def imports_text(self) -> str:
        """Formato dll!función, uno por línea, que entiende el importador del navegador."""
        seen, lines = set(), []
        for dll, fn in self.imports + self.delay_imports:
            key = (dll.lower(), fn)
            if key not in seen:
                seen.add(key)
                lines.append(f"{dll}!{fn}")
        return "\n".join(lines)


def _decode(b) -> str:
    return b.decode("ascii", "replace") if isinstance(b, (bytes, bytearray)) else str(b)


def analyze_pe(data: bytes, filename: str = "muestra") -> PEReport:
    if not data or data[:2] != b"MZ":
        raise PEError("El archivo no empieza con la firma MZ: no es un ejecutable PE de Windows.")
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        ])
    except pefile.PEFormatError as exc:
        raise PEError(f"pefile no pudo parsear el archivo: {exc}") from exc

    ts = pe.FILE_HEADER.TimeDateStamp
    try:
        ts_utc = dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        ts_utc = "inválido"
    try:
        imphash = pe.get_imphash() or ""
    except Exception:
        imphash = ""

    rep = PEReport(
        filename=filename, size=len(data),
        md5=hashlib.md5(data).hexdigest(), sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(), imphash=imphash,
        machine=MACHINES.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
        is_dll=pe.is_dll(), timestamp=ts, timestamp_utc=ts_utc,
    )

    for s in pe.sections:
        rep.sections.append(Section(
            name=_decode(s.Name).rstrip("\x00"), entropy=round(s.get_entropy(), 3),
            virtual_size=s.Misc_VirtualSize, raw_size=s.SizeOfRawData,
            executable=bool(s.Characteristics & 0x20000000)))

    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = _decode(entry.dll)
        for imp in entry.imports:
            if imp.name:
                rep.imports.append((dll, _decode(imp.name)))
            elif imp.ordinal is not None:
                rep.ordinals.append((dll, int(imp.ordinal)))
    for entry in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []) or []:
        dll = _decode(entry.dll)
        for imp in entry.imports:
            if imp.name:
                rep.delay_imports.append((dll, _decode(imp.name)))
            elif imp.ordinal is not None:
                rep.ordinals.append((dll, int(imp.ordinal)))
    pe.close()

    _add_warnings(rep)
    return rep


def _add_warnings(rep: PEReport) -> None:
    w = rep.warnings
    names = {fn.lower() for _, fn in rep.imports + rep.delay_imports}
    total = len(names) + len(rep.ordinals)
    if total == 0:
        w.append("No tiene importaciones: la resolución de APIs es totalmente dinámica o el binario está empacado.")
    elif total <= 10:
        w.append(f"Tabla de importaciones muy corta ({total} entradas): posible empaquetado o carga dinámica; "
                 "la matriz puede subestimar las capacidades reales.")
    if names and names <= DYNAMIC_RESOLUTION | {"exitprocess", "virtualalloc", "virtualprotect", "virtualfree"}:
        w.append("Solo importa funciones de carga dinámica y memoria: patrón típico de stub de empaquetador o loader.")
    for s in rep.sections:
        if s.name.lower() in PACKER_SECTIONS:
            w.append(f"Sección '{s.name}' con nombre asociado a empaquetadores conocidos.")
        if s.executable and s.entropy > 7.2:
            w.append(f"Sección ejecutable '{s.name}' con entropía {s.entropy:.2f}: indicio de código cifrado o empacado.")
        if s.executable and s.raw_size == 0 and s.virtual_size > 0:
            w.append(f"Sección ejecutable '{s.name}' vacía en disco que se llena en memoria (VirtualSize {s.virtual_size}).")
    now = dt.datetime.now(dt.timezone.utc).timestamp()
    if rep.timestamp == 0:
        w.append("TimeDateStamp en 0: marca de compilación borrada.")
    elif rep.timestamp == DELPHI_TS:
        w.append("TimeDateStamp 0x2A425E19: valor fijo típico de Delphi, no es la fecha real de compilación.")
    elif rep.timestamp > now + 86400:
        w.append(f"TimeDateStamp en el futuro ({rep.timestamp_utc}): probablemente falseado.")
