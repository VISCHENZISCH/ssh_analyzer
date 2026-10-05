use crate::analyzer::{Analyzer, IpStats};

pub trait Report {
    fn summary(&self) -> String;
}

pub fn print_report<T: Report>(item: &T) {
    println!("{}", item.summary());
}

impl Report for IpStats {
    fn summary(&self) -> String {
        if self.success_after_failures {
            format!(
                "[COMPROMISE] {} - {} échecs, utilisateurs ciblés : {:?}, connexion réussie après échecs",
                self.ip, self.failed_attempts, self.target_users
            )
        } else if self.failed_attempts > 0 {
            format!(
                "[SUSPECT]    {} - {} échecs, utilisateurs ciblés : {:?}",
                self.ip, self.failed_attempts, self.target_users
            )
        } else {
            format!("[OK]         {} - aucune anomalie", self.ip)
        }
    }
}

impl Report for Analyzer {
    fn summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "Lignes lues : {} | Lignes ignorées : {}",
            self.lines_read, self.lines_skipped
        ));
        lines.push(format!("Adresses IP distinctes : {}", self.stats.len()));
        lines.push(String::new());

        let mut entries: Vec<&IpStats> = self.stats.values().collect();
        entries.sort_by(|a, b| b.failed_attempts.cmp(&a.failed_attempts));

        for ip_stats in entries {
            lines.push(ip_stats.summary());
        }

        lines.join("\n")
    }
}
