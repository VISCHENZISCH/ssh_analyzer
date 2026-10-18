use std::net::IpAddr;
use crate::error::ParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshEvent {
    FailedAuth {
        user: String,
        ip: IpAddr,
        invalid_user: bool,
    },
    SuccessAuth {
        user: String,
        ip: IpAddr,
    },
    Other,
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

    if trimmed.contains("Failed password") || trimmed.contains("Failed publickey") {
        let invalid_user = trimmed.contains("invalid user");

        let ip = extract_ip(trimmed).ok_or_else(|| {
            ParseError::InvalidIp("missing or unparseable IP".to_string())
        })?;

        let user = extract_user(trimmed)
            .ok_or_else(|| ParseError::InvalidUser("missing".to_string()))?;

        return Ok(SshEvent::FailedAuth {
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
                user: "vischenzisch".to_string(),
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 10, 200)),
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
