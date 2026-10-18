# SSH Analyzer

[![Rust](https://img.shields.io/badge/Rust-1.82+-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()

> **Analyseur de logs SSH haute performance** - Détecte les attaques par force brute et les compromissions en analysant les fichiers `auth.log`.

---

## Fonctionnalités

- **Streaming mémoire optimisé** (`BufReader`) : lecture ligne par ligne sans saturer la RAM, idéal pour les fichiers de logs volumineux.
- **Support IPv4 & IPv6 complet** : validation et traitement natif des deux protocoles réseau.
- **Parsing SSH intelligent** : prise en charge des mots de passe, clés publiques (`Accepted publickey`), authentifications PAM et utilisateurs invalides.
- **Filtrage propre** : distinction automatique entre lignes SSH et autres services système (CRON, systemd), sans bruit dans le terminal.
- **Détection des menaces** :
  - **Suspect** (`[!]`) - IP dépassant le seuil d'échecs configuré
  - **Compromise** (`[!!]`) - Connexion réussie après une série de tentatives échouées
- **Génération de règles de remédiation** : export automatique de commandes de blocage pour `ufw` et `iptables` / `ip6tables`.
- **Export JSON** : intégration facile avec des outils de monitoring et SIEM (Wazuh, Splunk, ELK).
- **Affichage terminal enrichi** : coloration syntaxique dynamique pour une lecture rapide des alertes.
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

# Exemples
cargo run -- auth.log
cargo run -- auth.log 3
cargo run -- auth.log 3 --block-rules
cargo run -- auth.log --json
cargo run -- /var/log/auth.log -v
```

### Options disponibles

| Option | Description |
|---|---|
| `<FICHIER>` | Chemin vers le fichier `auth.log` à analyser |
| `[SEUIL]` | Seuil de tentatives échouées avant alerte (défaut : `5`) |
| `-b, --block-rules` | Génère les commandes de bannissement pare-feu (`ufw`, `iptables`) |
| `--json` | Exporte le rapport complet au format JSON |
| `-v, --verbose` | Affiche les détails d'analyse et les lignes ignorées |
| `-h, --help` | Affiche l'aide |

---

### Exemples de sortie

#### Rapport standard en console
```text
============= Rapport SSH =============

Lignes totales : 385 | Lignes SSH traitées : 257 | Autres daemons : 128 | Ignorées/Erreurs : 0
Adresses IP distinctes : 2

[!!] [COMPROMISE] 65.2.161.68 - 48 échecs, 3 succès, cibles : ["admin", "backup", "cyberjunkie", "root", "server_adm", "svc_account"], compromis après brute-force
     [OK]         203.101.190.9 - 0 échecs, 1 succès, aucune anomalie
```

#### Avec règles de blocage pare-feu (`--block-rules`)
```bash
============= Règles de pare-feu recommandées =============

# === Commandes UFW (Uncomplicated Firewall) ===
sudo ufw insert 1 deny from 65.2.161.68 comment 'SSH Analyzer Threat'

# === Commandes iptables ===
sudo iptables -I INPUT -s 65.2.161.68 -p tcp --dport 22 -j DROP
```

---

## Licence

Ce projet est distribué sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.
