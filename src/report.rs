use colored::Colorize;
use crate::analyzer::{Analyzer, IpStats, ThreatStatus};

pub trait Report {
    fn summary(&self, threshold: u32) -> String;
}

pub fn print_report<T: Report>(item: &T, threshold: u32) {
    println!("{}", item.summary(threshold));
}

#[derive(Debug, Clone, Copy)]
pub struct ReportOptions {
    pub threshold: u32,
    pub show_all: bool,
    pub top_n: Option<usize>,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            threshold: 5,
            show_all: false,
            top_n: None,
        }
    }
}

impl Report for IpStats {
    fn summary(&self, threshold: u32) -> String {
        let failed_users: Vec<&str> = self.failed_users.iter().map(|s| s.as_str()).collect();
        let success_users: Vec<&str> = self.success_users.iter().map(|s| s.as_str()).collect();

        let time_str = match (&self.first_seen, &self.last_seen) {
            (Some(first), Some(last)) if first == last => format!(" [{}]", first),
            (Some(first), Some(last)) => format!(" [{} -> {}]", first, last),
            _ => String::new(),
        };

        let invalid_str = if self.invalid_user_attempts > 0 {
            format!(" (dont {} inconnus)", self.invalid_user_attempts)
        } else {
            String::new()
        };

        match self.status(threshold) {
            ThreatStatus::Compromised => {
                format!(
                    "{} {} - {} échecs{}, {} succès, cibles : {:?}, compromis sur : {:?}, compromis après brute-force{}",
                    "[COMPROMISE]".red().bold(),
                    self.ip.to_string().bold(),
                    self.failed_attempts.to_string().red().bold(),
                    invalid_str.yellow(),
                    self.success_attempts.to_string().green(),
                    failed_users,
                    success_users,
                    time_str.dimmed()
                )
            }
            ThreatStatus::Suspect => {
                format!(
                    "{}    {} - {} échecs{}, {} succès, cibles : {:?}{}",
                    "[SUSPECT]".yellow().bold(),
                    self.ip.to_string().bold(),
                    self.failed_attempts.to_string().yellow().bold(),
                    invalid_str.yellow(),
                    self.success_attempts,
                    failed_users,
                    time_str.dimmed()
                )
            }
            ThreatStatus::Normal => {
                let targets = if !success_users.is_empty() {
                    &success_users
                } else {
                    &failed_users
                };
                format!(
                    "{}         {} - {} échecs, {} succès, comptes : {:?}{}",
                    "[OK]".green(),
                    self.ip,
                    self.failed_attempts,
                    self.success_attempts,
                    targets,
                    time_str.dimmed()
                )
            }
        }
    }
}

impl Analyzer {
    pub fn summary_with_options(&self, opts: &ReportOptions) -> String {
        let mut lines = Vec::new();
        let ssh_lines = self
            .lines_read
            .saturating_sub(self.non_ssh_lines)
            .saturating_sub(self.lines_skipped);

        let suspects_count = self.suspects(opts.threshold).len();
        let compromises_count = self.compromises(opts.threshold).len();

        lines.push(format!(
            "Lignes totales : {} | Lignes SSH traitées : {} | Autres daemons : {} | Ignorées/Erreurs : {}",
            self.lines_read.to_string().bold(),
            ssh_lines.to_string().cyan(),
            self.non_ssh_lines,
            if self.lines_skipped > 0 {
                self.lines_skipped.to_string().yellow().to_string()
            } else {
                self.lines_skipped.to_string()
            }
        ));
        lines.push(format!(
            "Adresses IP distinctes : {} | Menaces : {} suspectes, {} compromises",
            self.stats.len().to_string().cyan().bold(),
            suspects_count.to_string().yellow().bold(),
            compromises_count.to_string().red().bold()
        ));

        let top_targets = self.top_targeted_users(5);
        if !top_targets.is_empty() {
            let targets_str = top_targets
                .iter()
                .map(|(u, count)| format!("{}: {}", u.cyan(), count.to_string().bold()))
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!("Top comptes ciblés : {}", targets_str));
        }

        lines.push(String::new());

        let mut entries: Vec<&IpStats> = self.stats.values().collect();
        entries.sort_by_key(|a| std::cmp::Reverse(a.failed_attempts));

        let total_normal = entries
            .iter()
            .filter(|s| s.status(opts.threshold) == ThreatStatus::Normal)
            .count();

        let filtered_entries: Vec<&IpStats> = if opts.show_all {
            entries
        } else {
            entries
                .into_iter()
                .filter(|s| s.status(opts.threshold) != ThreatStatus::Normal)
                .collect()
        };

        if filtered_entries.is_empty() {
            lines.push(format!(
                "Aucune menace détectée (seuil : {} échecs). Utilisez --all pour afficher toutes les IP vérifiées.",
                opts.threshold
            ));
        } else {
            let display_entries = if let Some(limit) = opts.top_n {
                &filtered_entries[..filtered_entries.len().min(limit)]
            } else {
                &filtered_entries[..]
            };

            for ip_stats in display_entries {
                let badge = match ip_stats.status(opts.threshold) {
                    ThreatStatus::Compromised => "[!!] ".red().bold().to_string(),
                    ThreatStatus::Suspect => "[!]  ".yellow().bold().to_string(),
                    ThreatStatus::Normal => "     ".to_string(),
                };
                lines.push(format!("{}{}", badge, ip_stats.summary(opts.threshold)));
            }

            if !opts.show_all && total_normal > 0 {
                lines.push(String::new());
                lines.push(format!(
                    "[*] {} adresse(s) IP normale(s) masquée(s). Utilisez -a / --all pour afficher l'ensemble.",
                    total_normal
                ));
            }
        }

        lines.join("\n")
    }
}

impl Report for Analyzer {
    fn summary(&self, threshold: u32) -> String {
        self.summary_with_options(&ReportOptions {
            threshold,
            show_all: false,
            top_n: None,
        })
    }
}

/// Génère des règles de pare-feu prêtes à l'emploi pour bannir les IP suspectes ou compromises
pub fn generate_firewall_rules(analyzer: &Analyzer, threshold: u32) -> String {
    let mut rules = String::new();
    let mut threats: Vec<&IpStats> = analyzer
        .stats
        .values()
        .filter(|s| s.is_suspect(threshold))
        .collect();
    threats.sort_by_key(|a| std::cmp::Reverse(a.failed_attempts));

    if threats.is_empty() {
        return "# Aucune IP suspecte à bloquer pour le moment.\n".to_string();
    }

    // 1. nftables (Recommandé moderne)
    rules.push_str("# === Commandes nftables (Recommandé standard Linux moderne) ===\n");
    rules.push_str("# Configuration d'un ensemble de blocage SSH rapide :\n");
    for s in &threats {
        match s.ip {
            std::net::IpAddr::V4(ip) => {
                rules.push_str(&format!(
                    "sudo nft add element inet filter ssh_blacklist {{ {} }} 2>/dev/null || sudo nft add rule inet filter input ip saddr {} tcp dport 22 drop\n",
                    ip, ip
                ));
            }
            std::net::IpAddr::V6(ip) => {
                rules.push_str(&format!(
                    "sudo nft add element inet filter ssh_blacklist_v6 {{ {} }} 2>/dev/null || sudo nft add rule inet filter input ip6 saddr {} tcp dport 22 drop\n",
                    ip, ip
                ));
            }
        }
    }

    // 2. UFW
    rules.push_str("\n# === Commandes UFW (Uncomplicated Firewall) ===\n");
    for s in &threats {
        rules.push_str(&format!(
            "sudo ufw insert 1 deny from {} comment 'SSH Analyzer Threat'\n",
            s.ip
        ));
    }

    // 3. iptables / ip6tables
    rules.push_str("\n# === Commandes iptables ===\n");
    for s in &threats {
        let flag = match s.ip {
            std::net::IpAddr::V4(_) => "iptables",
            std::net::IpAddr::V6(_) => "ip6tables",
        };
        rules.push_str(&format!(
            "sudo {} -I INPUT -s {} -p tcp --dport 22 -j DROP\n",
            flag, s.ip
        ));
    }

    rules
}
