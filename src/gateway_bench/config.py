"""Configuration de la gateway app_server.py et emplacements du banc.

app_server.py se configure uniquement par variables d'environnement ; ses
valeurs par défaut pointent vers certs/ du prototype. Ce module les préremplit
avec la PKI de test (test_pki/out) et le port de la convention du banc (9444),
et sauvegarde/recharge des profils JSON pour rejouer un scénario.
"""
from __future__ import annotations

import json
import os
import socket
import sys
from dataclasses import asdict, dataclass, fields
from pathlib import Path

# gateway_bench/src/gateway_bench/config.py -> parents[3] = test_env
TEST_ENV_DIR = Path(__file__).resolve().parents[3]
PKI_DIR = TEST_ENV_DIR / "test_pki"
PKI_OUT = PKI_DIR / "out"
SETUP_PKI_SCRIPT = PKI_DIR / "setup_test_pki.sh"
PROTOTYPE_DIR = TEST_ENV_DIR / "zero-trust-firmware-delivery" / "firmware_delivery_prototype"
APP_SERVER_SCRIPT = PROTOTYPE_DIR / "src" / "app_server.py"
DEFAULT_PORT = 9444          # convention du banc : 9443 = OCPP, 9444 = gateway authority


def prototype_python() -> Path:
    """Python du venv poetry du prototype (requests, cryptography…)."""
    venv = PROTOTYPE_DIR / ".venv"
    return venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


@dataclass
class GatewayConfig:
    server_crt: str = str(PKI_OUT / "server_chain.crt")   # chaîne feuille + intermédiaire
    server_key: str = str(PKI_OUT / "server.key")
    ca_root: str = str(PKI_OUT / "root_ca.crt")           # ancre de vérification des clients
    ota_file: str = ""                                    # image servie par GET /ota/<serial>
    host: str = "0.0.0.0"
    port: int = DEFAULT_PORT
    renew_provisioner: str = "device-identity"
    renew_not_after: str = ""                             # forcer le not_after signé (tests)
    renew_omit_not_after: bool = False                    # T7 : réponse sans not_after
    python: str = ""                                      # vide = venv du prototype

    PATH_FIELDS = ("server_crt", "server_key", "ca_root", "ota_file", "python")

    def python_exe(self) -> Path:
        return Path(self.python) if self.python else prototype_python()

    def to_env(self, base: dict[str, str] | None = None) -> dict[str, str]:
        """Environnement de app_server.py (les clés de test absentes sont retirées)."""
        env = dict(os.environ if base is None else base)
        env.update({
            "SERVER_CRT": self.server_crt,
            "SERVER_KEY": self.server_key,
            "CA_ROOT": self.ca_root,
            "APP_HOST": self.host,
            "APP_PORT": str(self.port),
            "RENEW_PROVISIONER": self.renew_provisioner,
            "PYTHONUNBUFFERED": "1",          # journal en direct
            "PYTHONIOENCODING": "utf-8",
        })
        for key in ("OTA_FILE", "RENEW_NOT_AFTER", "RENEW_OMIT_NOT_AFTER"):
            env.pop(key, None)
        if self.ota_file:
            env["OTA_FILE"] = self.ota_file
        if self.renew_not_after:
            env["RENEW_NOT_AFTER"] = self.renew_not_after
        if self.renew_omit_not_after:
            env["RENEW_OMIT_NOT_AFTER"] = "1"
        return env

    # -- profils ------------------------------------------------------------------

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, ensure_ascii=False)

    @classmethod
    def from_dict(cls, raw: dict) -> "GatewayConfig":
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in raw.items() if k in names})

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json() + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "GatewayConfig":
        """Charge un profil ; ses chemins relatifs s'entendent par rapport au
        dossier du profil (profils livrés portables)."""
        path = Path(path)
        cfg = cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
        base = path.resolve().parent
        for name in cls.PATH_FIELDS:
            value = getattr(cfg, name)
            if value and not Path(value).is_absolute():
                setattr(cfg, name, str((base / value).resolve()))
        return cfg


def detect_lan_ip() -> str:
    """IP de la route par défaut (ZCE_LAN_IP prioritaire), sans émettre de paquet."""
    env = os.environ.get("ZCE_LAN_IP")
    if env:
        return env
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
