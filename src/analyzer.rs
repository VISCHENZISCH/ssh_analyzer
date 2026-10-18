use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use crate::parser::SshEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatStatus {
    Normal,
    Suspect,
    Compromised,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpStats {
    pub ip: IpAddr,
    pub failed_attempts: u32,
    pub success_attempts: u32,
    pub target_users: BTreeSet<String>,
    pub success_after_failures: bool,
}

impl IpStats {
    pub fn new(ip: IpAddr) -> Self {
        IpStats {
            ip,
            failed_attempts: 0,
            success_attempts: 0,
            target_users: BTreeSet::new(),
            success_after_failures: false,
        }
    }

    pub fn is_suspect(&self, threshold: u32) -> bool {
        self.failed_attempts >= threshold
    }

    pub fn is_compromised(&self, threshold: u32) -> bool {
        self.success_after_failures && self.is_suspect(threshold)
    }

    pub fn status(&self, threshold: u32) -> ThreatStatus {
        if self.is_compromised(threshold) {
            ThreatStatus::Compromised
        } else if self.is_suspect(threshold) {
            ThreatStatus::Suspect
        } else {
            ThreatStatus::Normal
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Analyzer {
    pub stats: HashMap<IpAddr, IpStats>,
    pub lines_read: u32,
    pub lines_skipped: u32,
    pub non_ssh_lines: u32,
}

impl Analyzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process(&mut self, event: SshEvent) {
        match event {
            SshEvent::FailedAuth {
                user,
                ip,
                invalid_user: _,
            } => {
                let entry = self.stats.entry(ip).or_insert_with(|| IpStats::new(ip));
                entry.failed_attempts += 1;
                entry.target_users.insert(user);
            }
            SshEvent::SuccessAuth { user, ip } => {
                let entry = self.stats.entry(ip).or_insert_with(|| IpStats::new(ip));
                entry.success_attempts += 1;
                entry.target_users.insert(user);
                if entry.failed_attempts > 0 {
                    entry.success_after_failures = true;
                }
            }
            SshEvent::Other => {}
        }
    }

    pub fn suspects(&self, threshold: u32) -> Vec<&IpStats> {
        self.stats.values().filter(|s| s.is_suspect(threshold)).collect()
    }

    pub fn compromises(&self, threshold: u32) -> Vec<&IpStats> {
        self.stats.values().filter(|s| s.is_compromised(threshold)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compromised_after_failures() {
        let mut analyzer = Analyzer::new();
        let test_ip: IpAddr = "10.0.0.1".parse().unwrap();

        for _ in 0..3 {
            analyzer.process(SshEvent::FailedAuth {
                user: "admin".to_string(),
                ip: test_ip,
                invalid_user: true,
            });
        }

        analyzer.process(SshEvent::SuccessAuth {
            user: "admin".to_string(),
            ip: test_ip,
        });

        let stats = analyzer.stats.get(&test_ip).unwrap();
        assert_eq!(stats.failed_attempts, 3);
        assert_eq!(stats.success_attempts, 1);
        assert!(stats.success_after_failures);
        assert!(stats.is_suspect(3));
        assert!(stats.is_compromised(3));
        assert_eq!(stats.status(3), ThreatStatus::Compromised);
        assert!(!stats.is_suspect(5));
        assert!(!stats.is_compromised(5));
        assert_eq!(stats.status(5), ThreatStatus::Normal);
    }
}
