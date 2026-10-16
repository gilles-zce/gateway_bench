"""Pare-feu Windows : une règle entrante autorise-t-elle le port de la gateway ?

On liste les ports des règles TCP entrantes actives « Autoriser » (PowerShell)
et on cherche le port dans ces listes (valeurs isolées, plages « a-b »,
« Any »). Résultat None si la question ne peut pas être tranchée (pas de
Windows, PowerShell en échec) : simple indication, jamais bloquant.

Lent (~30 s : un filtre de port par règle). Les variantes rapides
(`Get-NetFirewallPortFilter -Protocol` ou `-All`) renvoient « Accès refusé »
sans droits administrateur et omettent des règles : on garde la requête
complète, lancée en tâche de fond par la GUI et sur demande en ligne de
commande (`status --firewall`).
"""
from __future__ import annotations

import subprocess
import sys

_PS = (
    "Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow "
    "-ErrorAction SilentlyContinue | "
    "Get-NetFirewallPortFilter | Where-Object { $_.Protocol -in 'TCP','Any' } | "
    "ForEach-Object { ($_.LocalPort -join ',') }"
)


def port_allowed(lines: list[str], port: int) -> bool:
    for line in lines:
        for item in line.replace(" ", "").split(","):
            if not item:
                continue
            if item.lower() == "any":
                return True
            if "-" in item:
                lo, _, hi = item.partition("-")
                if lo.isdigit() and hi.isdigit() and int(lo) <= port <= int(hi):
                    return True
            elif item.isdigit() and int(item) == port:
                return True
    return False


def firewall_allows(port: int) -> bool | None:
    if sys.platform != "win32":
        return None
    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-Command", _PS], capture_output=True,
                              text=True, timeout=90, creationflags=subprocess.CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = proc.stdout.splitlines()
    if not lines:
        return None
    return port_allowed(lines, port)
