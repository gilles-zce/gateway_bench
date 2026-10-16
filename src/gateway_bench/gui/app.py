"""GUI Kivy du banc gateway : PKI (step-ca) en haut, gateway app_server.py au
milieu, journal commun en bas. Couche d'affichage seulement : la logique est
dans pki / certs / gateway / image (testés sans fenêtre).
"""
from __future__ import annotations

import datetime as _dt
import os
import threading
from pathlib import Path

os.environ.setdefault("KIVY_NO_ARGS", "1")

from kivy.config import Config  # noqa: E402

Config.set("graphics", "width", "1000")
Config.set("graphics", "height", "720")

from kivy.app import App  # noqa: E402
from kivy.clock import Clock  # noqa: E402
from kivy.lang import Builder  # noqa: E402
from kivy.metrics import dp  # noqa: E402
from kivy.uix.boxlayout import BoxLayout  # noqa: E402
from kivy.uix.button import Button  # noqa: E402
from kivy.uix.checkbox import CheckBox  # noqa: E402
from kivy.uix.filechooser import FileChooserListView  # noqa: E402
from kivy.uix.label import Label  # noqa: E402
from kivy.uix.popup import Popup  # noqa: E402
from kivy.uix.textinput import TextInput  # noqa: E402

from ..certs import check_server_cert  # noqa: E402
from ..config import PKI_OUT, TEST_ENV_DIR, GatewayConfig, detect_lan_ip  # noqa: E402
from ..firewall import firewall_allows  # noqa: E402
from ..gateway import AppServerProcess, GatewayError, classify, port_in_use, preflight  # noqa: E402
from ..image import parse_app_image  # noqa: E402
from ..pki import StepCa  # noqa: E402

ROW_H = dp(28)
LABEL_W = dp(240)       # colonne des libellés du formulaire gateway
GREEN, RED, ORANGE, GREY = "7CCB7C", "E05A4F", "E8A33D", "9A9A9A"
POLL_S = 5.0

KV = """
<Section@Label>:
    size_hint_y: None
    height: dp(28)
    bold: True
    halign: 'left'
    valign: 'middle'
    text_size: self.size
    color: (0.6, 0.75, 1, 1)

<Info@Label>:
    size_hint_y: None
    height: self.texture_size[1] + dp(6)
    text_size: self.width, None
    halign: 'left'
    valign: 'middle'
    markup: True
    padding: [dp(4), 0]

BoxLayout:
    orientation: 'vertical'
    padding: dp(8)
    spacing: dp(6)

    BoxLayout:
        size_hint_y: None
        height: dp(32)
        spacing: dp(6)
        Label:
            id: header
            markup: True
            halign: 'left'
            valign: 'middle'
            text_size: self.size
        Button:
            text: 'Charger profil…'
            size_hint_x: None
            width: dp(160)
            on_release: app.open_load_profile()
        Button:
            text: 'Enregistrer profil…'
            size_hint_x: None
            width: dp(180)
            on_release: app.open_save_profile()

    ScrollView:
        do_scroll_x: False
        BoxLayout:
            id: body
            orientation: 'vertical'
            size_hint_y: None
            height: self.minimum_height
            spacing: dp(4)

    Splitter:
        sizable_from: 'top'
        size_hint_y: None
        height: dp(220)
        min_size: dp(80)
        max_size: dp(700)
        BoxLayout:
            orientation: 'vertical'
            spacing: dp(3)
            BoxLayout:
                size_hint_y: None
                height: dp(26)
                spacing: dp(6)
                Label:
                    text: 'Journal'
                    halign: 'left'
                    valign: 'middle'
                    text_size: self.size
                Button:
                    text: 'Effacer'
                    size_hint_x: None
                    width: dp(100)
                    on_release: app.clear_log()
            TextInput:
                id: log_console
                readonly: True
                font_size: dp(12)
"""


def _color(text: str, hex_color: str) -> str:
    return f"[color={hex_color}]{text}[/color]"


class GatewayBenchApp(App):
    title = "Banc gateway — PKI de test (step-ca) et app_server.py"

    def build(self):
        self.ca = StepCa()
        self.gateway = AppServerProcess(on_line=self._on_gateway_line)
        self.lan_ip = detect_lan_ip()
        self.fields: dict[str, TextInput] = {}
        self._polling = False
        self._firewall: bool | None = None
        self._fw_pending = True
        root = Builder.load_string(KV)
        self.root_widget = root
        self._build_pki(root.ids.body)
        self._build_gateway(root.ids.body)
        self.apply_config(GatewayConfig())
        self._refresh_header()
        threading.Thread(target=self._check_firewall, daemon=True).start()
        Clock.schedule_once(lambda _dt: self.poll(), 0.5)
        Clock.schedule_interval(lambda _dt: self.poll(), POLL_S)
        return root

    def on_stop(self):
        # La gateway est un processus enfant : elle s'arrête avec la fenêtre.
        # step-ca reste lancée (d'autres outils en dépendent).
        self.gateway.stop()

    # ------------------------------------------------------------- construction

    def _row(self, *widgets, height=ROW_H) -> BoxLayout:
        row = BoxLayout(size_hint_y=None, height=height, spacing=dp(6))
        for w in widgets:
            row.add_widget(w)
        return row

    def _label(self, text: str, width: float | None = None, **kw) -> Label:
        lbl = Label(text=text, halign="right" if width else "left", valign="middle",
                    markup=True, **kw)
        if width:
            lbl.size_hint_x, lbl.width = None, width
        lbl.bind(size=lambda w, s: setattr(w, "text_size", s))
        return lbl

    def _button(self, text: str, handler, width: float = dp(150)) -> Button:
        b = Button(text=text, size_hint_x=None, width=width)
        b.bind(on_release=lambda *_: handler())
        return b

    def _build_pki(self, body: BoxLayout) -> None:
        from kivy.factory import Factory
        body.add_widget(Factory.Section(text="PKI de test — step-ca (WSL, https://localhost:9000)"))
        self.pki_status = self._label("…")
        self.pki_buttons = [self._button("Démarrer", self.on_pki_start, dp(120)),
                            self._button("Arrêter", self.on_pki_stop, dp(120)),
                            self._button("Journal step-ca", self.on_pki_log, dp(160))]
        body.add_widget(self._row(self.pki_status, *self.pki_buttons))
        self.cert_info = Factory.Info(text="")
        body.add_widget(self.cert_info)
        self.reissue_btn = self._button("Réémettre le certificat serveur pour l'IP LAN",
                                        self.on_reissue, dp(380))
        body.add_widget(self._row(self.reissue_btn, Label()))

    def _field(self, body, label: str, key: str, browse: bool = False, hint: str = "") -> None:
        ti = TextInput(multiline=False, write_tab=False, hint_text=hint,
                       padding=[dp(6), dp(5)], font_size=dp(13))
        self.fields[key] = ti
        widgets = [self._label(label, LABEL_W), ti]
        if browse:
            widgets.append(self._button("Parcourir…", lambda k=key: self._choose(k), dp(120)))
        body.add_widget(self._row(*widgets))

    def _build_gateway(self, body: BoxLayout) -> None:
        from kivy.factory import Factory
        body.add_widget(Factory.Section(text="Gateway mTLS — app_server.py (OTA terrain, renouvellement d'identité)"))
        self._field(body, "Certificat serveur (chaîne)", "server_crt", browse=True)
        self._field(body, "Clé serveur", "server_key", browse=True)
        self._field(body, "Racine CA (clients)", "ca_root", browse=True)
        self._field(body, "Image OTA servie", "ota_file", browse=True,
                    hint="GET /ota/<serial> — vide = 503")
        self.fields["ota_file"].bind(text=lambda *_: self._refresh_image())
        self.image_info = Factory.Info(text="")
        body.add_widget(self.image_info)
        self._field(body, "Port", "port")
        self._field(body, "Hôte d'écoute", "host")
        self._field(body, "Provisioner de renouvellement", "renew_provisioner")
        self._field(body, "not_after forcé (tests)", "renew_not_after",
                    hint="vide = durée du provisioner")
        self.t7 = CheckBox(size_hint_x=None, width=dp(32))
        body.add_widget(self._row(Label(size_hint_x=None, width=LABEL_W), self.t7,
                                  self._label(_color("T7 : réponses /identity/* SANS not_after "
                                                     "(test de la garde APPLY — jamais hors T7)",
                                                     ORANGE))))
        self.gw_status = self._label("…")
        self.gw_start = self._button("Démarrer", self.on_gateway_start, dp(120))
        self.gw_stop = self._button("Arrêter", self.on_gateway_stop, dp(120))
        body.add_widget(self._row(self.gw_status, self.gw_start, self.gw_stop, height=dp(36)))

    # ------------------------------------------------------------- configuration

    def collect_config(self) -> GatewayConfig:
        f = {k: v.text.strip() for k, v in self.fields.items()}
        try:
            port = int(f["port"])
        except ValueError as e:
            raise ValueError(f"port invalide : {f['port']!r}") from e
        return GatewayConfig(server_crt=f["server_crt"], server_key=f["server_key"],
                             ca_root=f["ca_root"], ota_file=f["ota_file"], host=f["host"] or "0.0.0.0",
                             port=port, renew_provisioner=f["renew_provisioner"] or "device-identity",
                             renew_not_after=f["renew_not_after"],
                             renew_omit_not_after=self.t7.active)

    def apply_config(self, cfg: GatewayConfig) -> None:
        for key in ("server_crt", "server_key", "ca_root", "ota_file", "host",
                    "renew_provisioner", "renew_not_after"):
            self.fields[key].text = str(getattr(cfg, key))
        self.fields["port"].text = str(cfg.port)
        self.t7.active = cfg.renew_omit_not_after
        self._refresh_image()

    def _refresh_image(self) -> None:
        path = self.fields["ota_file"].text.strip()
        if not path:
            self.image_info.text = _color("Aucune image : GET /ota répondra 503.", ORANGE)
            return
        if not Path(path).is_file():
            self.image_info.text = _color(f"Image introuvable : {path}", RED)
            return
        try:
            self.image_info.text = _color(parse_app_image(path).summary(), GREEN)
        except ValueError as e:
            self.image_info.text = _color(f"Servie telle quelle, mais {e}", ORANGE)

    def _refresh_header(self) -> None:
        fw = self._firewall
        port = self.fields["port"].text.strip() or "?"
        fw_text = (_color(f"pare-feu :{port} autorisé", GREEN) if fw
                   else _color("pare-feu : vérification en cours (~30 s)…" if self._fw_pending
                               else "pare-feu non vérifié", GREY) if fw is None
                   else _color(f"pare-feu : aucune règle entrante pour :{port}", RED))
        self.root_widget.ids.header.text = f"IP LAN : [b]{self.lan_ip}[/b]   —   {fw_text}"

    def _check_firewall(self) -> None:
        try:
            port = int(self.fields["port"].text.strip())
        except ValueError:
            return
        self._firewall = firewall_allows(port)
        self._fw_pending = False
        Clock.schedule_once(lambda _dt: self._refresh_header())

    # ------------------------------------------------------------- état

    def poll(self) -> None:
        if self._polling:
            return
        self._polling = True

        def work():
            try:
                st = self.ca.status()
                info, problems = check_server_cert(PKI_OUT / "server.crt", self.lan_ip)
                try:
                    port = int(self.fields["port"].text.strip())
                except ValueError:
                    port = 0
                listening = bool(port) and port_in_use(port)
                Clock.schedule_once(lambda _dt: self._show(st, info, problems, listening))
            finally:
                self._polling = False

        threading.Thread(target=work, daemon=True).start()

    def _show(self, st, info, problems, listening: bool) -> None:
        color = GREEN if st.healthy else ORANGE if st.running else RED if st.available else GREY
        detail = st.detail if len(st.detail) <= 60 else st.detail[:57] + "…"
        self.pki_status.text = f"État : {_color(st.label, color)}   [size=12sp]{detail}[/size]"
        if info:
            lines = [f"Certificat serveur : CN={info.subject_cn}, expire le "
                     f"{info.not_after:%Y-%m-%d}, SAN {', '.join(info.sans)}"]
        else:
            lines = []
        lines += [_color(f"⚠ {p}", RED) for p in problems] or [_color("Certificat serveur valable pour l'IP LAN.", GREEN)]
        self.cert_info.text = "\n".join(lines)
        if self.gateway.running:
            text = _color(f"en service — https://{self.lan_ip}:{self.gateway.config.port}", GREEN)
        elif listening:
            text = _color("arrêtée ici, mais le port est occupé par un autre processus", ORANGE)
        else:
            text = _color("arrêtée", GREY)
        self.gw_status.text = f"Gateway : {text}"
        self.gw_start.disabled = self.gateway.running
        self.gw_stop.disabled = not self.gateway.running

    # ------------------------------------------------------------- actions PKI

    def _background(self, tag: str, job, then=None) -> None:
        def work():
            try:
                result = job()
                if result:
                    self.log(str(result), tag)
            except Exception as e:  # noqa: BLE001 — afficher, ne pas tuer la GUI
                self.log(f"ERREUR : {e}", tag)
            finally:
                Clock.schedule_once(lambda _dt: (then or self.poll)())
        threading.Thread(target=work, daemon=True).start()

    def on_pki_start(self) -> None:
        self.log("Démarrage de step-ca…", "PKI")
        self._background("PKI", self.ca.start)

    def on_pki_stop(self) -> None:
        self._background("PKI", self.ca.stop)

    def on_pki_log(self) -> None:
        self._background("PKI", lambda: "Fin de ~/.step/ca.log :\n" + self.ca.log_tail())

    def on_reissue(self) -> None:
        ip = self.lan_ip
        self.log(f"Réémission du certificat serveur pour {ip} (setup_test_pki.sh)…", "PKI")

        def job():
            ok, text = self.ca.reissue_server_cert(ip)
            suffix = ("\nRedémarrer les serveurs qui chargent ce certificat (gateway, CSMS)."
                      if ok else "\nÉCHEC")
            return text + suffix
        self._background("PKI", job)

    # ------------------------------------------------------------- actions gateway

    def on_gateway_start(self) -> None:
        try:
            cfg = self.collect_config()
            errors, warnings = preflight(cfg)
        except ValueError as e:
            self.log(f"ERREUR de saisie : {e}", "Gateway")
            return
        for w in warnings:
            self.log(f"⚠ {w}", "Gateway")
        if errors:
            for e in errors:
                self.log(f"✗ {e}", "Gateway")
            return
        try:
            self.gateway.start(cfg)
            self.log(f"app_server.py lancé : https://{self.lan_ip}:{cfg.port} "
                     f"(image {Path(cfg.ota_file).name if cfg.ota_file else 'aucune'})", "Gateway")
        except GatewayError as e:
            self.log(f"✗ {e}", "Gateway")
        Clock.schedule_once(lambda _dt: self.poll(), 1.0)

    def on_gateway_stop(self) -> None:
        self.gateway.stop()
        self.poll()

    def _on_gateway_line(self, line: str) -> None:
        tag = classify(line)
        self.log(f"[{tag}] {line}" if tag else line, "app_server")

    # ------------------------------------------------------------- profils, fichiers

    def open_save_profile(self) -> None:
        def cb(path: str):
            target = Path(path)
            if target.is_dir():
                target = target / "gateway.json"
            if target.suffix != ".json":
                target = target.with_suffix(".json")
            try:
                self.collect_config().save(target)
                self.log(f"Profil enregistré : {target}", "Profil")
            except (OSError, ValueError) as e:
                self.log(f"ERREUR enregistrement : {e}", "Profil")
        self._open_chooser(cb, filters=["*.json"], save_mode=True)

    def open_load_profile(self) -> None:
        def cb(path: str):
            try:
                self.apply_config(GatewayConfig.load(path))
                self.log(f"Profil chargé : {path}", "Profil")
            except (OSError, ValueError, TypeError) as e:
                self.log(f"ERREUR chargement : {e}", "Profil")
        self._open_chooser(cb, filters=["*.json"])

    def _choose(self, key: str) -> None:
        def cb(path: str):
            self.fields[key].text = path
        self._open_chooser(cb)

    def _open_chooser(self, callback, filters=None, save_mode: bool = False) -> None:
        start = TEST_ENV_DIR.parent if TEST_ENV_DIR.parent.is_dir() else Path.home()
        content = BoxLayout(orientation="vertical", spacing=dp(4))
        chooser = FileChooserListView(path=str(start), filters=filters or [], dirselect=save_mode)
        path_input = TextInput(multiline=False, size_hint_y=None, height=ROW_H,
                               hint_text="Chemin (modifiable à la main)")
        chooser.bind(selection=lambda _w, sel: setattr(path_input, "text", sel[0]) if sel else None)
        content.add_widget(chooser)
        content.add_widget(path_input)
        popup = Popup(title="Enregistrer sous…" if save_mode else "Choisir un fichier",
                      content=content, size_hint=(0.9, 0.9))

        def validate(*_):
            path = path_input.text.strip() or (chooser.selection[0] if chooser.selection else "")
            if not path and save_mode:
                path = chooser.path
            if path:
                popup.dismiss()
                callback(path)

        buttons = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(6))
        ok, cancel = Button(text="Valider"), Button(text="Annuler")
        ok.bind(on_release=validate)
        cancel.bind(on_release=popup.dismiss)
        buttons.add_widget(ok)
        buttons.add_widget(cancel)
        content.add_widget(buttons)
        popup.open()

    # ------------------------------------------------------------- journal

    def log(self, message: str, tag: str | None = None) -> None:
        stamp = _dt.datetime.now().strftime("%H:%M:%S")
        prefix = f"{stamp} [{tag}] " if tag else f"{stamp} "
        lines = message.split("\n")
        text = "\n".join([prefix + lines[0]] + ["         " + line for line in lines[1:]])

        def append(_dt_):
            console = self.root_widget.ids.log_console
            console.text += text + "\n"
            console.cursor = (0, len(console.text))
        Clock.schedule_once(append)

    def clear_log(self) -> None:
        self.root_widget.ids.log_console.text = ""


def run_gui() -> None:
    GatewayBenchApp().run()
