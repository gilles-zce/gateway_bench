"""Pilotage de step-ca dans WSL (PKI de test), sans Vault ni local_server.

Mêmes commandes que test_pki/setup_test_pki.sh et start_wsl_stack.sh :
lancement `step-ca ~/.step/config/ca.json --password-file
~/.step/provisioner.pass`, santé par `step ca health` sur https://localhost:9000.
Tout passe par `wsl -e bash -lc` ; le lanceur est injectable pour les tests.
"""
from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .config import PKI_OUT, SETUP_PKI_SCRIPT

CA_URL = "https://localhost:9000"
STEP_ROOT = "~/.step/certs/root_ca.crt"
CA_CONFIG = "~/.step/config/ca.json"
PASS_FILE = "~/.step/provisioner.pass"
CA_LOG = "~/.step/ca.log"

Runner = Callable[[str, float], subprocess.CompletedProcess]


def wsl_path(path: str | Path) -> str:
    """C:\\x\\y -> /mnt/c/x/y."""
    p = str(Path(path).resolve()).replace("\\", "/")
    if len(p) > 1 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


def wsl_run(script: str, timeout: float = 30.0) -> subprocess.CompletedProcess:
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    return subprocess.run(["wsl", "-e", "bash", "-lc", script], capture_output=True,
                          text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, creationflags=flags)


@dataclass(frozen=True)
class PkiStatus:
    available: bool          # WSL joignable et step / step-ca installés
    running: bool            # processus step-ca présent
    healthy: bool            # `step ca health` = ok
    detail: str

    @property
    def label(self) -> str:
        if not self.available:
            return "indisponible"
        if self.running and self.healthy:
            return "en service"
        if self.running:
            return "démarrée mais en défaut"
        return "arrêtée"


class StepCa:
    def __init__(self, run: Runner = wsl_run):
        self._run = run

    def _call(self, script: str, timeout: float = 30.0) -> tuple[bool, str]:
        try:
            proc = self._run(script, timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, f"WSL injoignable : {e}"
        return proc.returncode == 0, (proc.stdout + proc.stderr).strip()

    def status(self) -> PkiStatus:
        ok, out = self._call(
            "command -v step >/dev/null && command -v step-ca >/dev/null "
            f"&& test -f {CA_CONFIG} && echo TOOLS_OK; "
            "pgrep -x step-ca >/dev/null && echo RUNNING || echo STOPPED; "
            f"step ca health --ca-url {CA_URL} --root {STEP_ROOT} 2>&1 | head -1", timeout=20)
        if "TOOLS_OK" not in out:
            if ok or "RUNNING" in out or "STOPPED" in out:   # WSL répond, outils absents
                out = "step / step-ca absents ou ~/.step non initialisé"
            return PkiStatus(False, False, False, out or "WSL injoignable")
        lines = [line.strip() for line in out.splitlines()]
        running = "RUNNING" in lines
        health = lines[-1] if lines else ""
        healthy = health == "ok"
        return PkiStatus(True, running, healthy, f"{CA_URL} : {health or 'pas de réponse'}")

    def start(self) -> str:
        # setsid + nohup : le processus survit à la fin de la commande wsl.
        _, out = self._call(
            "if ! pgrep -x step-ca >/dev/null; then "
            f"setsid nohup step-ca {CA_CONFIG} --password-file {PASS_FILE} "
            f"> {CA_LOG} 2>&1 < /dev/null & sleep 3; echo STARTED; "
            "else echo ALREADY; fi", timeout=30)
        return "step-ca déjà lancée" if "ALREADY" in out else "step-ca lancée"

    def stop(self) -> str:
        _, out = self._call("pkill -x step-ca && sleep 1 && echo STOPPED || echo NOT_RUNNING")
        return "step-ca arrêtée" if "STOPPED" in out else "step-ca n'était pas lancée"

    def log_tail(self, lines: int = 40) -> str:
        _, out = self._call(f"tail -n {int(lines)} {CA_LOG} 2>/dev/null")
        return out

    def reissue_server_cert(self, lan_ip: str, out_dir: Path = PKI_OUT,
                            script: Path = SETUP_PKI_SCRIPT) -> tuple[bool, str]:
        """Supprime out/server.crt puis relance setup_test_pki.sh <IP> : le
        certificat serveur est réémis avec localhost, 127.0.0.1 et l'IP LAN.
        L'ancre (root_ca) ne change pas : rien à reflasher côté prise."""
        return self._call(f"rm -f '{wsl_path(out_dir)}/server.crt' '{wsl_path(out_dir)}/server_chain.crt' "
                          f"&& bash '{wsl_path(script)}' '{lan_ip}'", timeout=120)
