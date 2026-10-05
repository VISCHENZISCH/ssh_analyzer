use std::collections::HashMap;
use crate::parser::SshEvent;

#[derive(Debug)]
pub struct IpStats {
    pub ip: String,
    pub failed_attempts: u32,
    pub target_users: Vec<String>,
    pub success_after_failures: bool,
}

impl IpStats {
   
    pub fn new(ip: &str) -> Self {
        IpStats {
            ip: ip.to_string(),
            failed_attempts: 0,
            target_users: Vec::new(),
            success_after_failures: false,
        }
    }

    pub fn is_suspect(&self, threshold: u32) -> bool {
        self.failed_attempts >= threshold
    }

    pub fn is_compromised(&self, threshold: u32) -> bool {
        self.success_after_failures && self.is_suspect(threshold)
    }
}


#[derive(Debug)]
pub struct Analyzer {
    pub stats: HashMap<String, IpStats>,
    pub lines_read: u32,
    pub lines_skipped: u32,
}

impl Analyzer {
    pub fn new() -> Self {
        Analyzer {
            stats: HashMap::new(),
            lines_read: 0,
            lines_skipped: 0,
        }
    }

    pub fn process(&mut self, event: SshEvent) {
        match event {
            SshEvent::FailedAuth {
                user,
                ip,
                invalid_user: _,
            } => {
                let entry = self
                    .stats
                    .entry(ip.clone())
                    .or_insert_with(|| IpStats::new(&ip));
                entry.failed_attempts += 1;
                if !entry.target_users.contains(&user) {
                    entry.target_users.push(user);
                }
            }
            SshEvent::SuccessAuth { user: _, ip } => {
                let entry = self
                    .stats
                    .entry(ip.clone())
                    .or_insert_with(|| IpStats::new(&ip));
                if entry.failed_attempts > 0 {
                    entry.success_after_failures = true;
                }
            }
            
            SshEvent::Other => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::SshEvent;

    #[test]
    fn test_compromised_after_failures() {
        let mut analyzer = Analyzer::new();

        for _ in 0..3 {
            analyzer.process(SshEvent::FailedAuth {
                user: "admin".to_string(),
                ip: "10.0.0.1".to_string(),
                invalid_user: true,
            });
        }


        analyzer.process(SshEvent::SuccessAuth {
            user: "admin".to_string(),
            ip: "10.0.0.1".to_string(),
        });

        let stats = analyzer.stats.get("10.0.0.1").unwrap();
        assert_eq!(stats.failed_attempts, 3);
        assert!(stats.success_after_failures);
        assert!(stats.is_suspect(3));
        assert!(stats.is_compromised(3));
        assert!(!stats.is_suspect(5));
        assert!(!stats.is_compromised(5));
    }
}
