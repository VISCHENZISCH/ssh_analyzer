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
    pub invalid_user_attempts: u32,
    pub failed_users: BTreeSet<String>,
    pub success_users: BTreeSet<String>,
    pub success_after_failures: bool,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

impl IpStats {
    pub fn new(ip: IpAddr) -> Self {
        IpStats {
            ip,
            failed_attempts: 0,
            success_attempts: 0,
            invalid_user_attempts: 0,
            failed_users: BTreeSet::new(),
            success_users: BTreeSet::new(),
            success_after_failures: false,
            first_seen: None,
            last_seen: None,
        }
    }

    /// Retourne l'ensemble de tous les utilisateurs ciblés (en échec ou succès)
    pub fn all_users(&self) -> BTreeSet<String> {
        self.failed_users.union(&self.success_users).cloned().collect()
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

    fn update_timestamps(&mut self, timestamp: Option<String>) {
        if let Some(ts) = timestamp {
            if self.first_seen.is_none() {
                self.first_seen = Some(ts.clone());
            }
            self.last_seen = Some(ts);
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Analyzer {
    pub stats: HashMap<IpAddr, IpStats>,
    pub user_failures: HashMap<String, u32>,
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
                timestamp,
                user,
                ip,
                invalid_user,
            } => {
                *self.user_failures.entry(user.clone()).or_insert(0) += 1;
                let entry = self.stats.entry(ip).or_insert_with(|| IpStats::new(ip));
                entry.failed_attempts += 1;
                if invalid_user {
                    entry.invalid_user_attempts += 1;
                }
                entry.failed_users.insert(user);
                entry.update_timestamps(timestamp);
            }
            SshEvent::SuccessAuth {
                timestamp,
                user,
                ip,
            } => {
                let entry = self.stats.entry(ip).or_insert_with(|| IpStats::new(ip));
                entry.success_attempts += 1;
                entry.success_users.insert(user);
                if entry.failed_attempts > 0 {
                    entry.success_after_failures = true;
                }
                entry.update_timestamps(timestamp);
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

    pub fn top_targeted_users(&self, limit: usize) -> Vec<(String, u32)> {
        let mut list: Vec<(String, u32)> = self
            .user_failures
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        list.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        list.truncate(limit);
        list
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
                timestamp: Some("Oct  5 10:15:01".to_string()),
                user: "admin".to_string(),
                ip: test_ip,
                invalid_user: true,
            });
        }

        analyzer.process(SshEvent::SuccessAuth {
            timestamp: Some("Oct  5 10:15:10".to_string()),
            user: "root".to_string(),
            ip: test_ip,
        });

        let stats = analyzer.stats.get(&test_ip).unwrap();
        assert_eq!(stats.failed_attempts, 3);
        assert_eq!(stats.success_attempts, 1);
        assert_eq!(stats.invalid_user_attempts, 3);
        assert!(stats.failed_users.contains("admin"));
        assert!(stats.success_users.contains("root"));
        assert_eq!(stats.first_seen.as_deref(), Some("Oct  5 10:15:01"));
        assert_eq!(stats.last_seen.as_deref(), Some("Oct  5 10:15:10"));
        assert!(stats.success_after_failures);
        assert!(stats.is_suspect(3));
        assert!(stats.is_compromised(3));
        assert_eq!(stats.status(3), ThreatStatus::Compromised);
        assert!(!stats.is_suspect(5));
        assert!(!stats.is_compromised(5));
        assert_eq!(stats.status(5), ThreatStatus::Normal);
    }

    #[test]
    fn test_top_targeted_users() {
        let mut analyzer = Analyzer::new();
        let ip: IpAddr = "1.1.1.1".parse().unwrap();

        for _ in 0..5 {
            analyzer.process(SshEvent::FailedAuth {
                timestamp: None,
                user: "root".to_string(),
                ip,
                invalid_user: false,
            });
        }
        for _ in 0..2 {
            analyzer.process(SshEvent::FailedAuth {
                timestamp: None,
                user: "admin".to_string(),
                ip,
                invalid_user: true,
            });
        }

        let top = analyzer.top_targeted_users(10);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0], ("root".to_string(), 5));
        assert_eq!(top[1], ("admin".to_string(), 2));
    }
}
