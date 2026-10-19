# SSH Analyzer

[![Rust](https://img.shields.io/badge/Rust-1.82+-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()

> **Analyseur de logs SSH haute performance** - Détecte les attaques par force brute et les compromissions en analysant les fichiers `auth.log` (fichiers bruts, compressés `.gz` ou pipelines `stdin`).

---

## Fonctionnalités

- **Streaming mémoire optimisé** (`BufReader`) : lecture ligne par ligne sans saturer la RAM, idéal pour les fichiers volumineux.
- **Support des fichiers compressés (`.gz`) & `stdin`** : décompression transparente à la volée des archives de logs (`auth.log.2.gz`) et lecture depuis des pipelines Unix (`journalctl -u ssh | ssh_analyzer -`).
- **Support IPv4 & IPv6 complet** : validation et traitement natif des deux protocoles réseau.
- **Analyse temporelle & Fenêtre d'attaque** : extraction des horodatages (Syslog standard et ISO 8601 / RFC 3339) pour calculer la période d'activité (`first_seen -> last_seen`).
- **Analyse granulaire des cibles & Détection de dictionnaire** :
  - Distinction entre comptes ciblés en échec (`failed_users`) et compte(s) ayant permis la compromission (`success_users`).
  - Détection et comptage des tentatives sur utilisateurs inexistants / inconnus (`invalid user`).
  - Classement des **Top comptes les plus ciblés**.
- **Détection des menaces** :
  - **Suspect** (`[!]`) - IP dépassant le seuil d'échecs configuré.
  - **Compromise** (`[!!]`) - Connexion réussie après une série de tentatives échouées.
- **Génération de règles de remédiation** : export automatique de commandes de blocage pour **`nftables`** (standard moderne), **`ufw`** et **`iptables` / `ip6tables`**, avec export possible sous forme de script shell exécutable (`--save-rules`).
- **Export JSON** : intégration facile avec des outils de monitoring et SIEM (Wazuh, Splunk, ELK).
- **Filtrage intelligent de la console** : affichage centré sur les alertes par défaut, avec option `-a, --all` pour inspecter l'ensemble des IP légitimes, et `--top <N>` pour cibler les attaquants majeurs.
- **Code de retour pour l'automatisation** : code de sortie `2` en cas d'intrusion avérée (pratique pour scripts bash / alertes cron).

---

## Installation

```bash
git clone https://github.com/VISCHENZISCH/ssh_analyzer.git
cd ssh_analyzer
cargo build --release
```

Le binaire sera disponible dans `target/release/ssh_analyzer`.

---

## Utilisation

```bash
# Syntaxe générale
ssh_analyzer [OPTIONS] <fichier_log> [seuil]

# Exemples classiques
cargo run -- auth.log
cargo run -- auth.log 3
cargo run -- auth.log 3 --block-rules
cargo run -- auth.log --json

# Analyse d'archives compressées (.gz)
cargo run -- /var/log/auth.log.2.gz 5

# Utilisation en pipeline Unix (stdin via "-")
journalctl -u ssh -o short-iso | cargo run -- - 5
cat /var/log/auth.log | cargo run -- - 3

# Génération et sauvegarde directe du script de pare-feu
cargo run -- auth.log 5 --save-rules ban_threats.sh

# Afficher l'intégralité des IP (y compris légitimes [OK])
cargo run -- auth.log --all
```

### Options disponibles

| Option | Description |
|---|---|
| `<FICHIER>` | Chemin vers le fichier `auth.log` à analyser (ou `-` pour `stdin`) |
| `[SEUIL]` | Seuil de tentatives échouées avant alerte (défaut : `5`) |
| `-a, --all` | Affiche toutes les IP analysées (y compris le trafic légitime `[OK]`) |
| `--top <N>` | Limite l'affichage aux N premières adresses IP les plus agressives |
| `-b, --block-rules` | Génère et affiche les commandes de bannissement pare-feu (`nftables`, `ufw`, `iptables`) |
| `--save-rules <FICHIER>` | Enregistre les règles de pare-feu générées dans un script bash exécutable |
| `--json` | Exporte le rapport complet au format JSON |
| `-v, --verbose` | Affiche les détails d'analyse et les lignes ignorées |
| `-h, --help` | Affiche l'aide |

---

### Exemples de sortie

#### Rapport standard en console
```text
============= Rapport SSH =============

Lignes totales : 385 | Lignes SSH traitées : 257 | Autres daemons : 128 | Ignorées/Erreurs : 0
Adresses IP distinctes : 2 | Menaces : 1 suspectes, 1 compromises
Top comptes ciblés : server_adm: 12, svc_account: 11, admin: 10, backup: 9, root: 6

[!!] [COMPROMISE] 65.2.161.68 - 48 échecs (dont 33 inconnus), 3 succès, cibles : ["admin", "backup", "root", "server_adm", "svc_account"], compromis sur : ["cyberjunkie", "root"], compromis après brute-force [Mar  6 06:31:33 -> Mar  6 06:37:34]

ℹ️  1 adresse(s) IP normale(s) masquée(s). Utilisez -a / --all pour afficher l'ensemble.
```

#### Avec règles de blocage pare-feu (`--block-rules`)
```bash
============= Règles de pare-feu recommandées =============

# === Commandes nftables (Recommandé standard Linux moderne) ===
# Configuration d'un ensemble de blocage SSH rapide :
sudo nft add element inet filter ssh_blacklist { 65.2.161.68 } 2>/dev/null || sudo nft add rule inet filter input ip saddr 65.2.161.68 tcp dport 22 drop

# === Commandes UFW (Uncomplicated Firewall) ===
sudo ufw insert 1 deny from 65.2.161.68 comment 'SSH Analyzer Threat'

# === Commandes iptables ===
sudo iptables -I INPUT -s 65.2.161.68 -p tcp --dport 22 -j DROP
```

---

## Licence

Ce projet est distribué sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.
