# SSH Analyzer

[![Rust](https://img.shields.io/badge/Rust-1.82+-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()

> **Analyseur de logs SSH** - Détecte les tentatives de brute-force et les compromissions en analysant les fichiers `auth.log`.

---

## Fonctionnalités

- **Parsing intelligent** des lignes `sshd` : échecs, succès, événements inconnus
- **Statistiques par IP** : nombre d'échecs, utilisateurs ciblés, compromissions
- **Détection de menaces** :
  - **Suspect** (`[!]`) - IP dépassant le seuil d'échecs
  - **Compromise** (`[!!]`) - Connexion réussie après de multiples échecs
- **Validation stricte** des adresses IPv4
- **Lecture de fichier** avec gestion d'erreurs robuste (`Result`, `From`, `?`)

---

## Installation

```bash
git clone https://github.com/VISCHENZISCH/ssh_analyzer.git
cd ssh_analyzer
cargo build --release
```

Le binaire sera dans `target/release/ssh_analyzer`.

---

## Utilisation

```bash
# Syntaxe
ssh_analyzer <fichier_log> [seuil]

# Exemples
cargo run -- auth.log
cargo run -- auth.log 3
cargo run -- /var/log/auth.log
```

### Exemple de sortie

```
[SKIP] ligne 10 : empty line
[SKIP] ligne 11 : unrecognized SSH event
[SKIP] ligne 12 : invalid IP address: invalid_ip

============= Rapport SSH =============

Lignes lues : 12 | Lignes ignorées : 3
Adresses IP distinctes : 3

[SUSPECT]    192.168.10.100 - 3 échecs, utilisateurs ciblés : ["root", "Hacker01", "test"]
[COMPROMISE] 192.168.10.23  - 3 échecs, utilisateurs ciblés : ["Hacker02", "admin", "Job"], connexion réussie après échecs
[OK]         192.168.10.200 - aucune anomalie

--- Détails par IP ---

[!]  [SUSPECT]    192.168.10.100 - 3 échecs, utilisateurs ciblés : ["root", "Hacker01", "test"]
[!!] [COMPROMISE] 192.168.10.23  - 3 échecs, utilisateurs ciblés : ["Hacker02", "admin", "Job"]
     [OK]         192.168.10.200 - aucune anomalie
```

---

## Licence

Ce projet est distribué sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.
