use std::net::IpAddr;
use crate::error::ParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshEvent {
    FailedAuth {
        timestamp: Option<String>,
        user: String,
        ip: IpAddr,
        invalid_user: bool,
    },
    SuccessAuth {
        timestamp: Option<String>,
        user: String,
        ip: IpAddr,
    },
    Other,
}

pub fn extract_timestamp(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let parts: Vec<&str> = trimmed.split_whitespace().take(4).collect();
    if parts.is_empty() {
        return None;
    }

    // Check ISO 8601 / RFC 3339 format (ex: 2024-03-06T06:19:54... ou 2024-03-06 06:19:54)
    if parts[0].len() >= 10 && parts[0].as_bytes()[4] == b'-' && parts[0].as_bytes()[7] == b'-' {
        if parts[0].contains('T') {
            return Some(parts[0].to_string());
        } else if parts.len() >= 2 && parts[1].contains(':') {
            return Some(format!("{} {}", parts[0], parts[1]));
        }
    }

    // Check Syslog standard format (ex: "Mar  6 06:19:54" ou "Oct 15 10:15:01")
    if parts.len() >= 3 {
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        if MONTHS.contains(&parts[0]) && parts[2].contains(':') {
            return Some(format!("{} {:>2} {}", parts[0], parts[1], parts[2]));
        }
    }

    None
}

pub fn extract_ip(line: &str) -> Option<IpAddr> {
    if let Some(after_from) = line.split(" from ").nth(1) {
        let token = after_from.split_whitespace().next()?;
        let clean = token.trim_matches(|c| c == '[' || c == ']' || c == ':' || c == ',');
        if let Ok(ip) = clean.parse::<IpAddr>() {
            return Some(ip);
        }
        if let Some(ip_part) = token.strip_prefix('[')
            && let Some(end_bracket) = ip_part.find(']')
            && let Ok(ip) = ip_part[..end_bracket].parse::<IpAddr>()
        {
            return Some(ip);
        }
    }
    if let Some(after_rhost) = line.split("rhost=").nth(1) {
        let token = after_rhost.split_whitespace().next()?;
        let clean = token.trim_matches(|c| c == '[' || c == ']' || c == ':' || c == ',');
        if let Ok(ip) = clean.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    None
}

pub fn extract_user(line: &str) -> Option<&str> {
    if let Some(after) = line.split("for invalid user ").nth(1) {
        return after.split_whitespace().next();
    }
    if let Some(after) = line.split("for ").nth(1) {
        return after.split_whitespace().next();
    }
    if let Some(after) = line.split("user=").nth(1) {
        let user = after.split_whitespace().next()?;
        if !user.is_empty() {
            return Some(user);
        }
    }
    None
}

pub fn parse_line(line: &str) -> Result<SshEvent, ParseError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(ParseError::EmptyLine);
    }

    if !trimmed.contains("sshd[") {
        return Err(ParseError::NotSshEvent);
    }

    let timestamp = extract_timestamp(trimmed);

    if trimmed.contains("Failed password") || trimmed.contains("Failed publickey") {
        let invalid_user = trimmed.contains("invalid user");

        let ip = extract_ip(trimmed).ok_or_else(|| {
            ParseError::InvalidIp("missing or unparseable IP".to_string())
        })?;

        let user = extract_user(trimmed)
            .ok_or_else(|| ParseError::InvalidUser("missing".to_string()))?;

        return Ok(SshEvent::FailedAuth {
            timestamp,
            user: user.to_string(),
            ip,
            invalid_user,
        });
    }

    if trimmed.contains("Accepted password")
        || trimmed.contains("Accepted publickey")
        || trimmed.contains("Accepted keyboard-interactive")
    {
        let ip = extract_ip(trimmed).ok_or_else(|| {
            ParseError::InvalidIp("missing or unparseable IP".to_string())
        })?;

        let user = extract_user(trimmed)
            .ok_or_else(|| ParseError::InvalidUser("missing".to_string()))?;

        return Ok(SshEvent::SuccessAuth {
            timestamp,
            user: user.to_string(),
            ip,
        });
    }

    Ok(SshEvent::Other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_failed_auth_ipv4() {
        let line = "Oct  5 10:15:01 server sshd[12345]: Failed password for Hacker02 from 192.168.10.23 port 22 ssh2";
        let result = parse_line(line).unwrap();
        assert_eq!(
            result,
            SshEvent::FailedAuth {
                timestamp: Some("Oct  5 10:15:01".to_string()),
                user: "Hacker02".to_string(),
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 10, 23)),
                invalid_user: false,
            }
        );
    }

    #[test]
    fn test_parse_failed_auth_ipv6() {
        let line = "Oct  5 10:15:01 server sshd[12345]: Failed password for invalid user admin from 2001:db8::1 port 22 ssh2";
        let result = parse_line(line).unwrap();
        let expected_ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            result,
            SshEvent::FailedAuth {
                timestamp: Some("Oct  5 10:15:01".to_string()),
                user: "admin".to_string(),
                ip: expected_ip,
                invalid_user: true,
            }
        );
    }

    #[test]
    fn test_parse_success_auth_publickey() {
        let line = "Oct  5 10:15:10 server sshd[12347]: Accepted publickey for vischenzisch from 192.168.10.200 port 22 ssh2: RSA SHA256:abc";
        let result = parse_line(line).unwrap();
        assert_eq!(
            result,
            SshEvent::SuccessAuth {
                timestamp: Some("Oct  5 10:15:10".to_string()),
                user: "vischenzisch".to_string(),
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 10, 200)),
            }
        );
    }

    #[test]
    fn test_parse_iso_timestamp() {
        let line = "2024-03-06T06:19:54.123456+00:00 server sshd[1465]: Accepted password for root from 1.2.3.4 port 42825 ssh2";
        let result = parse_line(line).unwrap();
        assert_eq!(
            result,
            SshEvent::SuccessAuth {
                timestamp: Some("2024-03-06T06:19:54.123456+00:00".to_string()),
                user: "root".to_string(),
                ip: "1.2.3.4".parse().unwrap(),
            }
        );
    }

    #[test]
    fn test_parse_empty_line() {
        let result = parse_line("");
        assert_eq!(result, Err(ParseError::EmptyLine));
    }

    #[test]
    fn test_parse_non_sshd_line() {
        let line = "Oct  5 10:15:50 server kernel: corrupted line without sshd marker";
        let result = parse_line(line);
        assert_eq!(result, Err(ParseError::NotSshEvent));
    }

    #[test]
    fn test_parse_other_sshd_event() {
        let line = "Mar  6 06:19:54 ip-172-31-35-28 sshd[1465]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)";
        let result = parse_line(line).unwrap();
        assert_eq!(result, SshEvent::Other);
    }
}
