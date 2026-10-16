"""Contrôle du certificat serveur de la PKI de test (test_pki/out/server.crt).

Piège rencontré : le certificat est émis avec les SAN de l'IP LAN du jour de
son émission ; après un changement de réseau, la prise (hostname check actif)
refuse la gateway et le CSMS de test. On signale donc l'IP LAN absente des SAN,
l'expiration proche et le fichier manquant.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

EXPIRY_WARNING = timedelta(days=7)


@dataclass(frozen=True)
class CertInfo:
    subject_cn: str
    not_after: datetime
    dns_names: tuple[str, ...]
    ip_addresses: tuple[str, ...]

    @property
    def sans(self) -> tuple[str, ...]:
        return self.dns_names + self.ip_addresses


def cert_info(path: str | Path) -> CertInfo:
    """Premier certificat du fichier PEM (la feuille, pour une chaîne)."""
    cert = x509.load_pem_x509_certificate(Path(path).read_bytes())
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = tuple(san.get_values_for_type(x509.DNSName))
        ips = tuple(str(ip) for ip in san.get_values_for_type(x509.IPAddress))
    except x509.ExtensionNotFound:
        dns, ips = (), ()
    return CertInfo(subject_cn=cn[0].value if cn else "", not_after=cert.not_valid_after_utc,
                    dns_names=dns, ip_addresses=ips)


def check_server_cert(path: str | Path, lan_ip: str,
                      now: datetime | None = None) -> tuple[CertInfo | None, list[str]]:
    """(infos, problèmes) ; une liste vide = certificat utilisable avec cette IP."""
    path = Path(path)
    if not path.is_file():
        return None, [f"certificat serveur absent : {path} (lancer setup_test_pki.sh)"]
    try:
        info = cert_info(path)
    except ValueError as e:
        return None, [f"certificat serveur illisible : {e}"]
    now = now or datetime.now(timezone.utc)
    problems = []
    if info.not_after <= now:
        problems.append(f"certificat serveur EXPIRÉ depuis le {info.not_after:%Y-%m-%d}")
    elif info.not_after - now < EXPIRY_WARNING:
        problems.append(f"certificat serveur expire bientôt ({info.not_after:%Y-%m-%d})")
    try:
        ipaddress.ip_address(lan_ip)
        if lan_ip not in info.ip_addresses:
            problems.append(f"l'IP LAN {lan_ip} n'est pas dans les SAN ({', '.join(info.sans)}) : "
                            "la prise refusera le serveur — réémettre le certificat")
    except ValueError:
        problems.append(f"IP LAN invalide : {lan_ip!r}")
    return info, problems
