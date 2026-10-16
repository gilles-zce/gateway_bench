"""Processus app_server.py : vérifications préalables, lancement, journal, arrêt."""
from __future__ import annotations

import re
import socket
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path

from .config import APP_SERVER_SCRIPT, PROTOTYPE_DIR, GatewayConfig
from .image import parse_app_image


class GatewayError(Exception):
    pass


def port_in_use(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def preflight(cfg: GatewayConfig, script: Path = APP_SERVER_SCRIPT,
              in_use: Callable[[int], bool] = port_in_use) -> tuple[list[str], list[str]]:
    """(erreurs bloquantes, avertissements) avant de lancer app_server.py."""
    errors, warnings = [], []
    if not cfg.python_exe().is_file():
        errors.append(f"Python du prototype introuvable : {cfg.python_exe()} "
                      "(poetry install dans firmware_delivery_prototype)")
    if not Path(script).is_file():
        errors.append(f"app_server.py introuvable : {script}")
    for label, value in (("certificat serveur", cfg.server_crt), ("clé serveur", cfg.server_key),
                         ("racine CA", cfg.ca_root)):
        if not value or not Path(value).is_file():
            errors.append(f"{label} introuvable : {value or '(vide)'}")
    if not 1 <= int(cfg.port) <= 65535:
        errors.append(f"port invalide : {cfg.port}")
    elif in_use(int(cfg.port)):
        errors.append(f"port {cfg.port} déjà utilisé (une autre gateway tourne-t-elle ?)")
    if not cfg.ota_file:
        warnings.append("aucune image OTA : GET /ota/<serial> répondra 503")
    elif not Path(cfg.ota_file).is_file():
        warnings.append(f"image OTA introuvable : {cfg.ota_file} — GET /ota répondra 503")
    else:
        try:
            parse_app_image(cfg.ota_file)
        except ValueError as e:
            warnings.append(f"image OTA servie telle quelle mais {e}")
    if cfg.renew_omit_not_after:
        warnings.append("T7 actif : les réponses /identity/* n'auront PAS de not_after")
    if cfg.renew_not_after:
        warnings.append(f"not_after forcé à {cfg.renew_not_after} pour les identités signées")
    return errors, warnings


# Lignes de app_server.py mises en évidence dans le journal.
_PATTERNS = (
    ("REFUS", re.compile(r"REFUSED|rejected connection", re.I)),
    ("ERREUR", re.compile(r"Traceback|Error|failed", re.I)),
    ("OK", re.compile(r"served|identity signed|mTLS gateway on", re.I)),
)


def classify(line: str) -> str | None:
    for tag, pattern in _PATTERNS:
        if pattern.search(line):
            return tag
    return None


class AppServerProcess:
    """app_server.py en processus enfant, avec le Python du prototype."""

    def __init__(self, on_line: Callable[[str], None], popen=subprocess.Popen,
                 script: Path = APP_SERVER_SCRIPT):
        self._on_line = on_line
        self._popen = popen
        self._script = script
        self._proc: subprocess.Popen | None = None
        self._stopping = False
        self.config: GatewayConfig | None = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def returncode(self) -> int | None:
        return None if self._proc is None else self._proc.poll()

    def start(self, cfg: GatewayConfig) -> list[str]:
        """Lance app_server.py ; renvoie les avertissements, lève GatewayError."""
        if self.running:
            raise GatewayError("app_server.py tourne déjà")
        errors, warnings = preflight(cfg, self._script)
        if errors:
            raise GatewayError(" ; ".join(errors))
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        self._proc = self._popen(
            [str(cfg.python_exe()), "-u", str(self._script)], cwd=str(PROTOTYPE_DIR),
            env=cfg.to_env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
            creationflags=flags)
        self.config = cfg
        self._stopping = False
        threading.Thread(target=self._pump, args=(self._proc,), daemon=True).start()
        return warnings

    def _pump(self, proc) -> None:
        for line in proc.stdout:
            self._on_line(line.rstrip())
        code = proc.wait()
        if self._stopping:
            self._on_line("[gateway] app_server.py arrêté")
        else:
            # Arrêt spontané : certificat illisible, port pris, exception…
            self._on_line(f"[gateway] app_server.py terminé de lui-même (code {code}) "
                          "— voir les lignes précédentes")

    def stop(self, timeout: float = 3.0) -> None:
        if not self.running:
            return
        self._stopping = True
        self._proc.terminate()
        try:
            self._proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout)
