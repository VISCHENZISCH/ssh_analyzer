use colored::Colorize;
use crate::analyzer::{Analyzer, IpStats, ThreatStatus};

pub trait Report {
    fn summary(&self, threshold: u32) -> String;
}

pub fn print_report<T: Report>(item: &T, threshold: u32) {
    println!("{}", item.summary(threshold));
}

impl Report for IpStats {
    fn summary(&self, threshold: u32) -> String {
        let users: Vec<&str> = self.target_users.iter().map(|s| s.as_str()).collect();
        match self.status(threshold) {
            ThreatStatus::Compromised => {
                format!(
                    "{} {} - {} échecs, {} succès, cibles : {:?}, compromis après brute-force",
                    "[COMPROMISE]".red().bold(),
                    self.ip.to_string().bold(),
                    self.failed_attempts.to_string().red().bold(),
                    self.success_attempts.to_string().green(),
                    users
                )
            }
            ThreatStatus::Suspect => {
                format!(
                    "{}    {} - {} échecs, {} succès, cibles : {:?}",
                    "[SUSPECT]".yellow().bold(),
                    self.ip.to_string().bold(),
                    self.failed_attempts.to_string().yellow().bold(),
                    self.success_attempts,
                    users
                )
            }
            ThreatStatus::Normal => {
                format!(
                    "{}         {} - {} échecs, {} succès, aucune anomalie",
                    "[OK]".green(),
                    self.ip,
                    self.failed_attempts,
                    self.success_attempts
                )
            }
        }
    }
}

impl Report for Analyzer {
    fn summary(&self, threshold: u32) -> String {
        let mut lines = Vec::new();
        let ssh_lines = self
            .lines_read
            .saturating_sub(self.non_ssh_lines)
            .saturating_sub(self.lines_skipped);

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
            "Adresses IP distinctes : {}",
            self.stats.len().to_string().cyan().bold()
        ));
        lines.push(String::new());

        let mut entries: Vec<&IpStats> = self.stats.values().collect();
        entries.sort_by_key(|a| std::cmp::Reverse(a.failed_attempts));

        for ip_stats in entries {
            let badge = match ip_stats.status(threshold) {
                ThreatStatus::Compromised => "[!!] ".red().bold().to_string(),
                ThreatStatus::Suspect => "[!]  ".yellow().bold().to_string(),
                ThreatStatus::Normal => "     ".to_string(),
            };
            lines.push(format!("{}{}", badge, ip_stats.summary(threshold)));
        }

        lines.join("\n")
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

    rules.push_str("# === Commandes UFW (Uncomplicated Firewall) ===\n");
    for s in &threats {
        rules.push_str(&format!(
            "sudo ufw insert 1 deny from {} comment 'SSH Analyzer Threat'\n",
            s.ip
        ));
    }

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
