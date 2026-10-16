"""Logique du banc gateway, sans Kivy, sans WSL ni réseau."""
import ipaddress
import json
import struct
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from gateway_bench import cli
from gateway_bench.certs import check_server_cert
from gateway_bench.config import DEFAULT_PORT, PKI_OUT, GatewayConfig
from gateway_bench.firewall import port_allowed
from gateway_bench.gateway import classify, preflight
from gateway_bench.image import parse_app_image
from gateway_bench.pki import StepCa, wsl_path

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)


# --- configuration -------------------------------------------------------------------

def test_defaults_point_to_the_test_pki_and_port_9444():
    cfg = GatewayConfig()
    assert Path(cfg.server_crt) == PKI_OUT / "server_chain.crt"
    assert Path(cfg.ca_root) == PKI_OUT / "root_ca.crt"
    assert cfg.port == DEFAULT_PORT == 9444


def test_env_sets_app_server_variables_and_drops_unset_test_keys():
    cfg = GatewayConfig(ota_file="C:/fw.bin", port=9555)
    env = cfg.to_env({"RENEW_OMIT_NOT_AFTER": "1", "RENEW_NOT_AFTER": "x", "PATH": "p"})
    assert env["OTA_FILE"] == "C:/fw.bin" and env["APP_PORT"] == "9555"
    assert env["SERVER_CRT"] == cfg.server_crt and env["CA_ROOT"] == cfg.ca_root
    assert "RENEW_OMIT_NOT_AFTER" not in env and "RENEW_NOT_AFTER" not in env
    assert env["PYTHONUNBUFFERED"] == "1" and env["PATH"] == "p"


def test_env_test_switches():
    env = GatewayConfig(renew_omit_not_after=True, renew_not_after="2026-11-01T00:00:00Z").to_env({})
    assert env["RENEW_OMIT_NOT_AFTER"] == "1"
    assert env["RENEW_NOT_AFTER"] == "2026-11-01T00:00:00Z"
    assert "OTA_FILE" not in env   # vide : app_server garde son défaut (503)


def test_profile_roundtrip_with_relative_paths(tmp_path):
    (tmp_path / "fw").mkdir()
    profile = tmp_path / "p.json"
    profile.write_text(json.dumps({"ota_file": "fw/a.bin", "port": 9500, "unknown": 1}),
                       encoding="utf-8")
    cfg = GatewayConfig.load(profile)
    assert Path(cfg.ota_file) == (tmp_path / "fw" / "a.bin").resolve()
    assert cfg.port == 9500
    cfg.save(tmp_path / "q.json")
    assert GatewayConfig.load(tmp_path / "q.json").ota_file == cfg.ota_file


# --- image ESP-IDF ---------------------------------------------------------------------

def make_image(path: Path, project="ZCE_PLUG_ocpp_n16r8", version="1", magic=0xABCD5432,
               first=0xE9) -> Path:
    header = bytes([first]) + bytes(23)
    seg = bytes(8)
    desc = struct.pack("<II", magic, 0) + bytes(8)
    desc += version.encode().ljust(32, b"\0") + project.encode().ljust(32, b"\0")
    desc += b"10:22:57".ljust(16, b"\0") + b"Oct 14 2026".ljust(16, b"\0")
    desc += b"v5.4.2".ljust(32, b"\0") + bytes(range(32))
    path.write_bytes(header + seg + desc.ljust(256, b"\0") + bytes(1000))
    return path


def test_image_fields(tmp_path):
    info = parse_app_image(make_image(tmp_path / "a.bin"))
    assert (info.project_name, info.version, info.date, info.time, info.idf_version) == (
        "ZCE_PLUG_ocpp_n16r8", "1", "Oct 14 2026", "10:22:57", "v5.4.2")
    assert info.elf_sha256.startswith("000102") and "ZCE_PLUG_ocpp_n16r8" in info.summary()


@pytest.mark.parametrize("kw", [dict(first=0x00), dict(magic=0x12345678)])
def test_not_an_app_image(tmp_path, kw):
    with pytest.raises(ValueError):
        parse_app_image(make_image(tmp_path / "b.bin", **kw))


# --- certificat serveur ----------------------------------------------------------------

def make_cert(path: Path, ips=("127.0.0.1", "192.168.1.39"), days=90) -> Path:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "zce-test-server")])
    san = [x509.DNSName("localhost")] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .sign(key, hashes.SHA256()))
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def test_cert_ok_for_the_lan_ip(tmp_path):
    info, problems = check_server_cert(make_cert(tmp_path / "s.crt"), "192.168.1.39", now=NOW)
    assert problems == [] and info.subject_cn == "zce-test-server"
    assert info.sans == ("localhost", "127.0.0.1", "192.168.1.39")


def test_cert_flags_a_lan_ip_missing_from_the_sans(tmp_path):
    # cas du 2026-10-14 : certificat émis sur 192.168.144.50, banc passé en 192.168.1.39
    _, problems = check_server_cert(make_cert(tmp_path / "s.crt", ips=("192.168.144.50",)),
                                    "192.168.1.39", now=NOW)
    assert any("192.168.1.39" in p and "SAN" in p for p in problems)


def test_cert_expiry_and_missing_file(tmp_path):
    _, problems = check_server_cert(make_cert(tmp_path / "s.crt", days=3), "192.168.1.39", now=NOW)
    assert any("expire bientôt" in p for p in problems)
    _, problems = check_server_cert(tmp_path / "absent.crt", "192.168.1.39", now=NOW)
    assert any("absent" in p for p in problems)


# --- step-ca (WSL simulé) ---------------------------------------------------------------

def fake_runner(stdout: str, code: int = 0, calls=None):
    def run(script, timeout):
        if calls is not None:
            calls.append(script)
        return subprocess.CompletedProcess(["wsl"], code, stdout, "")
    return run


def test_pki_status_healthy():
    st = StepCa(fake_runner("TOOLS_OK\nRUNNING\nok\n")).status()
    assert (st.available, st.running, st.healthy, st.label) == (True, True, True, "en service")


def test_pki_status_stopped_and_unavailable():
    st = StepCa(fake_runner("TOOLS_OK\nSTOPPED\nclient POST https://localhost:9000/health failed\n")).status()
    assert (st.running, st.healthy, st.label) == (False, False, "arrêtée")
    st = StepCa(fake_runner("STOPPED\n", code=1)).status()
    assert st.available is False and "non initialisé" in st.detail


def test_pki_wsl_missing():
    def boom(script, timeout):
        raise FileNotFoundError("wsl")
    st = StepCa(boom).status()
    assert st.available is False and st.label == "indisponible"


def test_pki_start_and_reissue_commands(tmp_path):
    calls = []
    ca = StepCa(fake_runner("STARTED\n", calls=calls))
    assert ca.start() == "step-ca lancée"
    assert "setsid nohup step-ca ~/.step/config/ca.json" in calls[-1]
    ca.reissue_server_cert("192.168.1.39", out_dir=Path("C:/workspace/test_env/test_pki/out"),
                           script=Path("C:/workspace/test_env/test_pki/setup_test_pki.sh"))
    assert "rm -f '/mnt/c/workspace/test_env/test_pki/out/server.crt'" in calls[-1]
    assert calls[-1].endswith("setup_test_pki.sh' '192.168.1.39'")


def test_wsl_path():
    assert wsl_path("C:\\workspace\\test_env") == "/mnt/c/workspace/test_env"


# --- gateway ------------------------------------------------------------------------------

def test_preflight_errors_and_warnings(tmp_path):
    cfg = GatewayConfig(server_crt=str(tmp_path / "none.crt"), python=str(tmp_path / "py.exe"))
    errors, warnings = preflight(cfg, script=tmp_path / "app_server.py", in_use=lambda p: True)
    text = " ".join(errors)
    assert "Python du prototype" in text and "app_server.py" in text
    assert "certificat serveur" in text and "port 9444 déjà utilisé" in text
    assert any("503" in w for w in warnings)


def test_preflight_ok_with_image_and_t7_warning(tmp_path):
    for name in ("py.exe", "app_server.py", "s.crt", "s.key", "root.crt"):
        (tmp_path / name).write_text("x")
    cfg = GatewayConfig(server_crt=str(tmp_path / "s.crt"), server_key=str(tmp_path / "s.key"),
                        ca_root=str(tmp_path / "root.crt"), python=str(tmp_path / "py.exe"),
                        ota_file=str(make_image(tmp_path / "fw.bin")), renew_omit_not_after=True)
    errors, warnings = preflight(cfg, script=tmp_path / "app_server.py", in_use=lambda p: False)
    assert errors == []
    assert warnings == ["T7 actif : les réponses /identity/* n'auront PAS de not_after"]


@pytest.mark.parametrize("line, tag", [
    ("[app-server] served /ota/ZCE-GO-x to verified device: ZCE-GO-x", "OK"),
    ("[app-server] /ota REFUSED: path=a cn=b", "REFUS"),
    ("[app-server] rejected connection: CERTIFICATE_VERIFY_FAILED", "REFUS"),
    ("Traceback (most recent call last):", "ERREUR"),
    ("[app-server] /identity/renew: identity signed for ZCE-GO-x", "OK"),
    ("rien de notable", None),
])
def test_classify(line, tag):
    assert classify(line) == tag


# --- pare-feu, ligne de commande --------------------------------------------------------

def test_firewall_port_parsing():
    assert port_allowed(["445", "9443-9444"], 9444) is True
    assert port_allowed(["8081,8767", "Any"], 9444) is True
    assert port_allowed(["8081,8767", "", "9500"], 9444) is False


def test_cli_dispatch_and_serve_options(tmp_path):
    assert cli.run([]) is None and cli.run(["gui"]) is None
    ns = cli.build_parser().parse_args(["serve", "--ota-file", str(tmp_path / "fw.bin"),
                                        "--port", "9555", "--omit-not-after"])
    cfg = cli.config_from_args(ns)
    assert cfg.port == 9555 and cfg.renew_omit_not_after is True
    assert Path(cfg.ota_file) == (tmp_path / "fw.bin").resolve()


def test_cli_image(tmp_path):
    out = []
    assert cli.cmd_image(make_image(tmp_path / "fw.bin", project="ZCE_PLUG_mqtt_n16r8"), out.append) == 0
    assert "ZCE_PLUG_mqtt_n16r8" in out[0]


# --- processus app_server (Popen simulé) ------------------------------------------------

class FakeProc:
    def __init__(self, lines, code):
        self.stdout = iter(lines)
        self._code = code
        self._done = False

    def poll(self):
        return self._code if self._done else None

    def wait(self, timeout=None):
        self._done = True
        return self._code

    def terminate(self):
        self._done = True

    kill = terminate


def _ready(tmp_path):
    for name in ("py.exe", "app_server.py", "s.crt", "s.key", "root.crt"):
        (tmp_path / name).write_text("x")
    return GatewayConfig(server_crt=str(tmp_path / "s.crt"), server_key=str(tmp_path / "s.key"),
                         ca_root=str(tmp_path / "root.crt"), python=str(tmp_path / "py.exe"),
                         port=59999)


def test_spontaneous_exit_is_reported_with_its_code(tmp_path):
    import time
    from gateway_bench.gateway import AppServerProcess
    lines = []
    proc = AppServerProcess(lines.append, popen=lambda *a, **k: FakeProc(["boom"], 1),
                            script=tmp_path / "app_server.py")
    proc.start(_ready(tmp_path))
    for _ in range(50):
        if any("terminé" in line for line in lines):
            break
        time.sleep(0.02)
    assert lines[0] == "boom"
    assert "terminé de lui-même (code 1)" in lines[-1]
