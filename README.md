gateway-bench
=============

Banc de pilotage de la **PKI de test** (step-ca dans WSL) et de la **gateway
mTLS** `app_server.py` du prototype `zero-trust-firmware-delivery`, utilisée
par les tests OTA terrain (`GET /ota/<serial>`) et de renouvellement
d'identité (`POST /identity/renew`) des prises et de la borne.

Il remplace la saisie à la main des variables d'environnement de
`app_server.py` et signale les pièges rencontrés en campagne :

- image OTA non renseignée → la gateway répond 503 (`OTA_FILE`) ;
- certificat serveur émis pour l'IP LAN d'un autre réseau → la prise refuse
  le serveur (hostname check) ;
- impossible de savoir quelle image est servie (OTA croisée OCPP / MQTT).

Périmètre : step-ca seul. Vault et `local_server` (`start_wsl_stack.sh`) ne
servent pas aux tests OTA / renouvellement de la prise et ne sont pas pilotés.

Installation
------------

```
poetry install
```

Prérequis : WSL avec `step` et `step-ca` installés et `~/.step` initialisé
(voir `test_pki/README.md`), et le venv du prototype
(`poetry install` dans `zero-trust-firmware-delivery/firmware_delivery_prototype`) :
`app_server.py` est lancé avec ce Python-là.

Interface graphique
-------------------

```
poetry run gateway-bench            # ou : poetry run gateway-bench gui
```

- **PKI de test — step-ca** : état (en service / arrêtée / en défaut /
  indisponible, rafraîchi toutes les 5 s), boutons Démarrer, Arrêter, Journal
  step-ca (`~/.step/ca.log`). **Certificat serveur** `test_pki/out/server.crt` :
  CN, expiration, SAN, avec alerte si l'IP LAN du jour n'est pas dans les SAN ou
  si l'expiration approche ; bouton **Réémettre le certificat serveur pour l'IP
  LAN** (supprime `out/server.crt` puis relance `setup_test_pki.sh <IP>` ;
  l'ancre ne change pas, rien à reflasher côté prise — redémarrer les serveurs
  qui chargent le certificat).
- **Gateway mTLS — app_server.py** : formulaire prérempli avec la PKI de test
  (`server_chain.crt`, `server.key`, `root_ca.crt`) et le port 9444 ; **image
  OTA** avec sa fiche lue dans l'en-tête ESP-IDF (nom de projet, version, date
  de compilation, IDF, taille) ; provisioner de renouvellement, `not_after`
  forcé et case **T7** (réponses sans `not_after`) avec avertissement.
  Démarrer / Arrêter ; vérifications préalables (fichiers, port libre, image) ;
  journal de `app_server.py` en direct, lignes marquées `[OK]` (servi, signé),
  `[REFUS]` (refus, handshake rejeté), `[ERREUR]`. Un arrêt spontané du
  processus est signalé avec son code.
- En-tête : IP LAN et règle de pare-feu entrante pour le port (vérification en
  tâche de fond, ~30 s).
- **Profils** JSON (Charger / Enregistrer) ; chemins relatifs au dossier du
  profil. Exemples dans `profiles/` : `ota_nominal_ocpp`,
  `ota_croisee_image_mqtt` (OTA-23), `t7_sans_not_after`.

Fermer la fenêtre arrête `app_server.py` ; step-ca reste lancée (d'autres
outils en dépendent).

Ligne de commande
-----------------

```
poetry run gateway-bench status [--firewall]    # PKI, certificat serveur, gateway (+ pare-feu, ~30 s)
poetry run gateway-bench pki start|stop|log
poetry run gateway-bench pki reissue [--ip IP]  # réémet le certificat serveur pour l'IP LAN
poetry run gateway-bench serve --profile profiles/ota_nominal_ocpp.json
poetry run gateway-bench serve --ota-file <image.bin> [--port 9444] [--not-after ISO] [--omit-not-after]
poetry run gateway-bench image <image.bin>      # fiche d'une image ESP-IDF
```

`serve` lance `app_server.py` au premier plan, journal en direct, Ctrl-C pour
arrêter. `status` rend 0 si step-ca est saine et le certificat serveur valable
pour l'IP LAN, 1 sinon (utilisable en script avant une campagne).

Organisation
------------

```
src/gateway_bench/
  config.py     GatewayConfig (variables de app_server.py, profils), emplacements, IP LAN
  pki.py        StepCa : état / démarrage / arrêt / journal / réémission, via `wsl -e bash -lc`
  certs.py      contrôle du certificat serveur (SAN, expiration)
  gateway.py    vérifications préalables, processus app_server.py, classement des lignes
  image.py      en-tête d'image applicative ESP-IDF (esp_app_desc_t)
  firewall.py   règle entrante du pare-feu Windows pour un port
  cli.py        sous-commandes
  gui/app.py    interface Kivy (affichage seulement)
tests/          logique testée sans Kivy, sans WSL ni réseau (poetry run pytest)
```
