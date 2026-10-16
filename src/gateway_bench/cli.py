"""Ligne de commande du banc gateway.

    gateway-bench                       GUI (défaut)
    gateway-bench status                état PKI, certificat serveur, gateway, pare-feu
    gateway-bench pki start|stop|log    step-ca dans WSL
    gateway-bench pki reissue [--ip IP] réémet le certificat serveur pour l'IP LAN
    gateway-bench serve [options]       app_server.py au premier plan (Ctrl-C pour arrêter)
    gateway-bench image FICHIER.bin     fiche d'une image applicative ESP-IDF
"""
from __future__ import annotations

import argparse
import threading
from pathlib import Path

from .certs import check_server_cert
from .config import PKI_OUT, GatewayConfig, detect_lan_ip
from .firewall import firewall_allows
from .gateway import AppServerProcess, GatewayError, classify, port_in_use, preflight
from .image import parse_app_image
from .pki import StepCa


def _print(text: str) -> None:
    # Écriture immédiate : le journal de la gateway doit suivre en direct,
    # y compris redirigé vers un fichier.
    print(text, flush=True)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gateway-bench",
                                description="Banc gateway : PKI de test (step-ca) et app_server.py")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("gui", help="interface graphique (défaut)")
    status = sub.add_parser("status", help="état de la PKI, du certificat serveur, de la gateway")
    status.add_argument("--firewall", action="store_true",
                        help="vérifier aussi la règle de pare-feu (~30 s)")
    pki = sub.add_parser("pki", help="step-ca dans WSL")
    pki.add_argument("action", choices=("start", "stop", "log", "reissue"))
    pki.add_argument("--ip", help="IP LAN pour reissue (défaut : ZCE_LAN_IP ou détection)")
    serve = sub.add_parser("serve", help="lance app_server.py au premier plan")
    serve.add_argument("--profile", type=Path, help="profil JSON (voir profiles/)")
    serve.add_argument("--ota-file", help="image servie par GET /ota/<serial>")
    serve.add_argument("--port", type=int, help="port de la gateway (défaut 9444)")
    serve.add_argument("--not-after", help="not_after forcé pour les identités signées")
    serve.add_argument("--omit-not-after", action="store_true",
                       help="T7 : réponses /identity/* sans not_after")
    img = sub.add_parser("image", help="fiche d'une image applicative ESP-IDF")
    img.add_argument("file", type=Path)
    return p


def config_from_args(ns: argparse.Namespace) -> GatewayConfig:
    cfg = GatewayConfig.load(ns.profile) if ns.profile else GatewayConfig()
    if ns.ota_file:
        cfg.ota_file = str(Path(ns.ota_file).resolve())
    if ns.port:
        cfg.port = ns.port
    if ns.not_after:
        cfg.renew_not_after = ns.not_after
    if ns.omit_not_after:
        cfg.renew_omit_not_after = True
    return cfg


def cmd_status(out=_print, firewall: bool = False) -> int:
    ip = detect_lan_ip()
    st = StepCa().status()
    out(f"IP LAN           : {ip}")
    out(f"PKI (step-ca)    : {st.label} — {st.detail}")
    info, problems = check_server_cert(PKI_OUT / "server.crt", ip)
    if info:
        out(f"Cert. serveur    : CN={info.subject_cn}, expire le {info.not_after:%Y-%m-%d}, "
            f"SAN {', '.join(info.sans)}")
    for problem in problems:
        out(f"  ⚠ {problem}")
    port = GatewayConfig().port
    out(f"Gateway :{port}    : {'en écoute' if port_in_use(port) else 'arrêtée'}")
    if firewall:
        fw = firewall_allows(port)
        out(f"Pare-feu :{port}   : "
            f"{'autorisé' if fw else 'non vérifié' if fw is None else 'AUCUNE règle entrante'}")
    return 0 if st.healthy and not problems else 1


def cmd_pki(action: str, ip: str | None, out=_print) -> int:
    ca = StepCa()
    if action == "start":
        out(ca.start())
        st = ca.status()
        out(f"PKI : {st.label} — {st.detail}")
        return 0 if st.healthy else 1
    if action == "stop":
        out(ca.stop())
        return 0
    if action == "log":
        out(ca.log_tail())
        return 0
    ip = ip or detect_lan_ip()
    out(f"Réémission du certificat serveur pour {ip}…")
    ok, text = ca.reissue_server_cert(ip)
    out(text)
    return 0 if ok else 1


def cmd_serve(cfg: GatewayConfig, out=_print) -> int:
    done = threading.Event()

    def on_line(line: str) -> None:
        tag = classify(line)
        out(f"[{tag}] {line}" if tag else line)
        if line.startswith(("[gateway] app_server.py terminé", "[gateway] app_server.py arrêté")):
            done.set()

    errors, warnings = preflight(cfg)
    for w in warnings:
        out(f"⚠ {w}")
    if errors:
        for e in errors:
            out(f"✗ {e}")
        return 1
    proc = AppServerProcess(on_line)
    try:
        proc.start(cfg)
        out(f"app_server.py lancé sur {cfg.host}:{cfg.port} — Ctrl-C pour arrêter")
        while not done.wait(0.5):
            pass
    except GatewayError as e:
        out(f"✗ {e}")
        return 1
    except KeyboardInterrupt:
        out("Arrêt de app_server.py…")
    finally:
        proc.stop()
    return 0


def cmd_image(path: Path, out=_print) -> int:
    try:
        out(parse_app_image(path).summary())
    except (OSError, ValueError) as e:
        out(f"✗ {e}")
        return 1
    return 0


def run(argv: list[str] | None = None) -> int | None:
    """Exécute la sous-commande ; None = lancer la GUI."""
    ns = build_parser().parse_args(argv)
    if ns.command in (None, "gui"):
        return None
    if ns.command == "status":
        return cmd_status(firewall=ns.firewall)
    if ns.command == "pki":
        return cmd_pki(ns.action, ns.ip)
    if ns.command == "serve":
        return cmd_serve(config_from_args(ns))
    return cmd_image(ns.file)
