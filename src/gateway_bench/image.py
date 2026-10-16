"""Fiche d'une image applicative ESP-IDF : nom de projet, version, date de build.

Format (ESP-IDF 5.x) : en-tête d'image de 24 octets (magic 0xE9), en-tête du
premier segment de 8 octets, puis `esp_app_desc_t` au début des données de ce
segment :
    magic_word u32 (0xABCD5432), secure_version u32, reserv1 u32[2],
    version char[32], project_name char[32], time char[16], date char[16],
    idf_ver char[32], app_elf_sha256 u8[32], …
Permet de voir d'un coup d'œil quelle image la gateway sert (OTA croisée :
ZCE_PLUG_ocpp_n16r8 contre ZCE_PLUG_mqtt_n16r8).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

IMAGE_MAGIC = 0xE9
APP_DESC_MAGIC = 0xABCD5432
APP_DESC_OFFSET = 24 + 8
APP_DESC_SIZE = 256


@dataclass(frozen=True)
class AppImageInfo:
    project_name: str
    version: str
    date: str
    time: str
    idf_version: str
    elf_sha256: str
    size: int

    def summary(self) -> str:
        return (f"{self.project_name} — version {self.version} — compilé le {self.date} "
                f"{self.time} — {self.idf_version} — {self.size / 1024:.0f} Kio")


def _cstr(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("ascii", "replace")


def parse_app_image(path: str | Path) -> AppImageInfo:
    """Lit l'en-tête ; ValueError si ce n'est pas une image applicative ESP-IDF."""
    path = Path(path)
    with path.open("rb") as f:
        head = f.read(APP_DESC_OFFSET + APP_DESC_SIZE)
    if len(head) < APP_DESC_OFFSET + APP_DESC_SIZE or head[0] != IMAGE_MAGIC:
        raise ValueError(f"pas une image applicative ESP-IDF (magic 0xE9 absent) : {path.name}")
    desc = head[APP_DESC_OFFSET:]
    (magic,) = struct.unpack_from("<I", desc, 0)
    if magic != APP_DESC_MAGIC:
        raise ValueError(f"esp_app_desc_t introuvable (magic 0x{magic:08X}) : {path.name}")
    return AppImageInfo(
        version=_cstr(desc[16:48]),
        project_name=_cstr(desc[48:80]),
        time=_cstr(desc[80:96]),
        date=_cstr(desc[96:112]),
        idf_version=_cstr(desc[112:144]),
        elf_sha256=desc[144:176].hex(),
        size=path.stat().st_size,
    )
